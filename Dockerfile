FROM python:3.13-alpine

# System-Abhängigkeiten für read-only Dateioperationen
RUN apk add --no-cache \
        findutils \
        coreutils \
        file \
        FROM python:3.13-alpine@sha256:18159b2be11d91b5781fe298b296ea1b760f844d484c3bd604cca5c86e5180b8

        ENV PYTHONDONTWRITEBYTECODE=1
        ENV PYTHONUNBUFFERED=1

        # System-Abhängigkeiten für read-only Dateioperationen
        RUN apk add --no-cache         findutils         coreutils         file         sqlite-libs         libmagic         openssl     && rm -rf /var/cache/apk/*

        WORKDIR /app

        COPY requirements.txt /app/requirements.txt
        RUN python -m pip install --no-cache-dir --require-hashes -r /app/requirements.txt

COPY src /app/src
COPY scripts/init-token.sh /app/scripts/init-token.sh
RUN chmod +x /app/scripts/init-token.sh

ENV PYTHONPATH=/app/src
ENV BRIDGE_TRANSPORT=http
ENV BRIDGE_HOST=0.0.0.0
ENV BRIDGE_PORT=8080

# Container startet als root; Umbrel App-Compose erzwingt read_only,
# cap_drop ALL + DAC_READ_SEARCH und no-new-privileges.
USER 0:0

ENTRYPOINT ["python", "-m", "umbrel_ro_bridge"]
