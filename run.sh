#!/bin/sh
set -e

if [ -z "$PORT" ]; then
  echo "WARNING: \$PORT not set by platform, defaulting to 8080 for local testing"
  PORT=8080
fi

echo "-------------------------------------------"
echo " VLESS-WS panel starting"
echo " Listen port : $PORT"
echo " WS path     : ${WSPATH:-/tun}"
echo "-------------------------------------------"

exec uvicorn app.main:app --host 0.0.0.0 --port "$PORT"
