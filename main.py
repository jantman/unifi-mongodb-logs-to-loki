#!/usr/bin/env python
"""
https://github.com/jantman/unifi-mongodb-logs-to-loki

MIT License

Copyright (c) 2024 Jason Antman

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import sys
import argparse
import logging
import os
from typing import List, Optional, Dict
import pickle
from datetime import datetime
import requests
from socket import gethostname
from json import JSONEncoder, dumps
from collections.abc import MutableMapping

from pymongo import MongoClient
from pymongo.errors import PyMongoError
import requests

logging.basicConfig(
    level=logging.WARNING,
    format="[%(asctime)s %(levelname)s] %(message)s"
)
logger: logging.Logger = logging.getLogger()

mongolog = logging.getLogger('pymongo')
mongolog.setLevel(logging.WARNING)
mongolog.propagate = True


def flatten(dictionary, parent_key='', separator='_'):
    # from: https://stackoverflow.com/a/6027615
    items = []
    for key, value in dictionary.items():
        new_key = parent_key + separator + key if parent_key else key
        if isinstance(value, MutableMapping):
            items.extend(flatten(value, new_key, separator=separator).items())
        else:
            items.append((new_key, value))
    return dict(items)


class MagicEncoder(JSONEncoder):

    def default(self, o):
        if isinstance(o, datetime):
            return o.isoformat('T')
        return super(MagicEncoder, self).default(o)


class UnifiToLoki:

    # If adding, be sure to also update UnifiToLoki._labels_for_change()
    WANTED_COLLECTIONS: List[str] = [
        'admin_activity_log',
        'alarm',
        'alert',
        'event',
        'inspection_log',
        'threat_log_view',
        'trigger_log',
    ]

    RESUME_TOKEN_FILE: str = 'resume_token.pkl'

    LOKI_PORT: int = 3100

    def __init__(self):
        if 'MONGODB_CONN_STR' not in os.environ:
            raise RuntimeError(
                'ERROR: Must set the MONGODB_CONN_STR environment variable.'
            )
        self.mongo_conn_str: str = os.environ['MONGODB_CONN_STR']
        if 'LOKI_HOST' not in os.environ:
            raise RuntimeError(
                'ERROR: Must set the LOKI_HOST environment variable.'
            )
        self.loki_host: str = os.environ['LOKI_HOST']
        self.resume_token: Optional[Dict] = None
        if os.path.exists(self.RESUME_TOKEN_FILE):
            with open(self.RESUME_TOKEN_FILE, 'rb') as fh:
                self.resume_token = pickle.load(fh)
        self.host: str
        if 'LOG_HOST' in os.environ:
            self.host = os.environ['LOG_HOST']
        else:
            self.host = gethostname()

    def run(self):
        logger.info('connecting to mongodb at: %s', self.mongo_conn_str)
        client: MongoClient = MongoClient(self.mongo_conn_str)
        logger.info('selecting DB: unifi')
        db = client.unifi
        try:
            with db.watch(
                [{"$match": {"operationType": "insert"}}],
                resume_after=self.resume_token
            ) as stream:
                logger.info('waiting for changes...')
                change: Dict
                for change in stream:
                    coll = change.get('ns', {}).get('coll')
                    if coll in self.WANTED_COLLECTIONS:
                        self.handle_change(change)
                    else:
                        logger.debug('Ignoring change for collection: %s', coll)
                    self.resume_token = change['_id']
                    with open(self.RESUME_TOKEN_FILE, 'wb') as fh:
                        pickle.dump(self.resume_token, fh, pickle.HIGHEST_PROTOCOL)
                        logger.debug('Wrote %s', self.RESUME_TOKEN_FILE)
        except PyMongoError as ex:
            print(f'PyMongoError: {ex}')
            raise

    def _labels_for_change(self, change: Dict) -> dict:
        result = {
            'source': 'unifi-mongodb-watcher',
            'job': 'unifi-mongodb-watcher',
            'host': self.host,
            'collection': change['collection'],
        }
        if change['collection'] == 'admin_activity_log':
            result['row_key'] = change.get('key', 'unknown')
        elif change['collection'] == 'alarm':
            result['row_key'] = change.get('key', 'unknown')
        elif change['collection'] == 'alert':
            result['row_key'] = change.get('key', 'unknown')
        elif change['collection'] == 'event':
            result['row_key'] = change.get('key', 'unknown')
        elif change['collection'] == 'inspection_log':
            result['row_key'] = change.get('log_source', '') + '/' + change.get('action', '')
        elif change['collection'] == 'threat_log_view':
            result['row_key'] = change.get('signature', 'unknown')
        elif change['collection'] == 'trigger_log':
            result['row_key'] = change.get('key', 'unknown')
        return result

    def handle_change(self, change: Dict):
        change['fullDocument']['collection'] = change['ns']['coll']
        change = change['fullDocument']
        logger.debug('Handle change: %s', change)
        change['_id'] = str(change['_id'])
        if len(str(change['time'])) > 10:
            change['time'] = change['time'] / 1000
        ts = str(int(change['time']) * 1000000000)
        logger.debug(change)
        url = f'http://{self.loki_host}:{self.LOKI_PORT}/loki/api/v1/push'
        flat: dict = flatten(change)
        payload = {
            'streams': [
                {
                    'stream': self._labels_for_change(change),
                    'values': [
                        [ts, dumps(flat, cls=MagicEncoder)]
                    ],
                }
            ]
        }
        j = dumps(payload, cls=MagicEncoder)
        logger.debug('POST to: %s', url)
        resp = requests.post(url, data=j, headers={'Content-type': 'application/json'})
        logger.debug('Loki responded HTTP %d: %s', resp.status_code, resp.text)
        try:
            resp.raise_for_status()
        except requests.exceptions.HTTPError:
            logger.error(
                'POST to %s returned HTTP %d: %s\nwith payload: %s',
                url, resp.status_code, resp.text, payload
            )
            raise


def parse_args(argv):
    p = argparse.ArgumentParser(description='UniFi to Loki logger')
    p.add_argument('-v', '--verbose', dest='verbose', action='store_true',
                   default=False, help='verbose output')
    args = p.parse_args(argv)
    return args


def set_log_info(l: logging.Logger):
    """set logger level to INFO"""
    set_log_level_format(
        l,
        logging.INFO,
        '%(asctime)s %(levelname)s:%(name)s:%(message)s'
    )


def set_log_debug(l: logging.Logger):
    """set logger level to DEBUG, and debug-level output format"""
    set_log_level_format(
        l,
        logging.DEBUG,
        "%(asctime)s [%(levelname)s %(filename)s:%(lineno)s - "
        "%(name)s.%(funcName)s() ] %(message)s"
    )


def set_log_level_format(lgr: logging.Logger, level: int, fmt: str):
    """Set logger level and format."""
    formatter = logging.Formatter(fmt=fmt)
    lgr.handlers[0].setFormatter(formatter)
    lgr.setLevel(level)


if __name__ == "__main__":
    args = parse_args(sys.argv[1:])

    # set logging level
    if args.verbose:
        set_log_debug(logger)
    else:
        set_log_info(logger)

    UnifiToLoki().run()
