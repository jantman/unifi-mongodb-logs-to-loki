# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Python daemon that uses MongoDB Change Streams to capture UniFi Network Server logs from MongoDB and forwards them to Grafana Loki. Single-file application (`main.py`, ~240 lines) deployed via Docker.

## Development Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Running

Requires two environment variables: `MONGODB_CONN_STR` (MongoDB connection string) and `LOKI_URL` (Loki push API endpoint). Optional `LOG_HOST` overrides hostname label.

```bash
./main.py        # normal mode
./main.py -v     # debug/verbose mode
```

## Building Docker Image

```bash
docker build -t unifi-mongodb-logs-to-loki .
```

## Architecture

**Single class `UnifiToLoki` in `main.py`** handles everything:

1. Connects to MongoDB and opens a Change Stream watching for inserts across the `ace` database (UniFi's DB)
2. Filters changes to 7 specific collections: `admin_activity_log`, `alarm`, `alert`, `event`, `inspection_log`, `threat_log_view`, `trigger_log`
3. Flattens nested MongoDB documents, applies collection-specific Loki labels (with a `row_key` derived differently per collection), and POSTs JSON payloads to Loki's push API
4. Persists a resume token (`resume_token.pkl`) after each successful push so the stream can resume after crashes

**Key design details:**
- `_labels_for_change()` maps each collection to its appropriate `row_key` label (e.g., `inspection_log` uses `log_source + action`, `threat_log_view` uses `signature`)
- `flatten()` utility recursively flattens nested dicts with underscore-separated keys
- `MagicEncoder` handles datetime serialization in JSON output
- Timestamps are converted to nanoseconds for Loki

## CI/CD

- `.github/workflows/build.yml` — pushes to main build and push Docker image to GHCR with SHA tag
- `.github/workflows/release.yml` — git tag pushes build and push to both Docker Hub and GHCR, then create a GitHub Release

## Dependencies

Only two runtime dependencies (`requirements.txt`): `pymongo` and `requests`.

## No Tests

There is no test suite in this project.
