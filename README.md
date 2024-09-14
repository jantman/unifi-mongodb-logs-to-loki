# unifi-mongodb-logs-to-loki

Python script and Docker image to ship UniFi Network Server logs from MongoDB to Loki

[![Project Status: WIP – Initial development is in progress, but there has not yet been a stable, usable release suitable for the public.](https://www.repostatus.org/badges/latest/wip.svg)](https://www.repostatus.org/#wip)

**IMPORTANT:** This is a personal project only. PRs are accepted, but this is not supported and "issues" will likely not be fixed or responded to. This is only for people who understand the details of everything invovled.

## Description

This is a very simple daemon that uses [MongoDB Change Streams](https://www.mongodb.com/docs/manual/changeStreams/) to react to additions to various MongoDB collections used by the [Ubiquiti UniFi Network Server](https://ui.com/download/releases/network-server) to store logs, and writes those logs to [Grafana Loki](https://grafana.com/oss/loki/). This is intended as a workaround for the fact that many important UniFi logs, such as IPS threats, blocked traffic, and various alarms, are only visible in the UI and are not written to any log files that can be easily aggregated to a centralized log system.

The MongoDB collections currently monitored are:

* `admin_activity_log` - Log of just admin activity; web logins and presumably some other things.
* `alarm` - IPS alerts, UniFi devices disconnected, etc.
* `alert` - General "alerts" like clients connecting/roaming/disconnecting, admin accesses, presumably other things.
* `event` - A whole bunch of different events including connect/disconnect/roaming broken down by user type (wired/wireless user/guest).
* `inspection_log` - Logs from traffic/firewall rules, i.e. blocked traffic.
* `threat_log_view` - Detailed information on threats ("triggers" in the UI).
* `trigger_log` - "Triggers" in the UI; seems to mainly be a condensed view of the threat log.

## Usage

This is really only intended to be run in Docker; if you need to run it locally, make your environment like the Docker container.

```
docker run \
    -e LOG_HOST="$(hostname)" \
    -e LOKI_URL=http://myloki:3100/loki/api/v1/push \
    -e MONGODB_CONN_STR=mongodb://mongo:27017/ \
    -v /opt/resume_token.pkl:/resume_token.pkl \
    jantman/unifi-mongodb-logs-to-loki:latest
```

MongoDB Change Streams can be resumed from the last handled record, i.e. if the service or host is restarted. The ``resume_token.pkl`` stores the pointer to the last change that was successfully sent to Loki. This file must be persisted outside the container (i.e. by mounting it in as a volume as shown in the above command) if you want to pick up where you left off before a restart or crash. If this is not persisted, then the container will always start handling new changes from the time it connects to MongoDB on. If for some reason the container repeatedly crashes while handling the same record, i.e. because of bad data, the easiest way to handle this is to delete the resume token file (and ignore all new logs from the time of that token until now).

### Environment Variables

* `LOKI_URL` (**required**) - Loki URL to ship logs to; e.g. `http://my-loki-instance/loki/api/v1/push`
* `MONGODB_CONN_STR` (**required**) - MongoDB [connection string](https://www.mongodb.com/docs/manual/reference/connection-string/); e.g. for MongoDB running on port 27017 of a host/container called `mongo`: `mongodb://mongo:27017/`
* `LOG_HOST` (_optional_) - Value to specify for the `host` label on log messages; if not specified, will use the Docker container hostname

## Debugging

For debugging, append `-v` to your `docker run` command, to run the entrypoint with debug-level logging.

## Development

Clone the repo, then in your clone:

```
python3 -mvenv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Release Process

Tag the repo. [GitHub Actions](https://github.com/jantman/zoneminder-loki/actions) will run a Docker build, push to Docker Hub and GHCR (GitHub Container Registry), and create a release on the repo.
