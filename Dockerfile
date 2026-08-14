FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN chmod +x run.sh

# Set these in Railway's Variables tab:
#   ADMIN_PASSWORD  -> panel login password (change from the default!)
#   WSPATH          -> websocket path, default /tun
#   SECRET_KEY      -> random string for session signing (optional, auto-generated if unset)
ENV ADMIN_PASSWORD="changeme123"
ENV WSPATH="/tun"

ENTRYPOINT ["./run.sh"]
