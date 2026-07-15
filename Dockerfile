FROM python:3.13-alpine@sha256:399babc8b49529dabfd9c922f2b5eea81d611e4512e3ed250d75bd2e7683f4b0

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# System-Abhängigkeiten für read-only Dateioperationen
RUN apk add --no-cache \
        findutils \
        coreutils \
        file \
        sqlite-libs \
        libmagic \
        openssl \
    && rm -rf /var/cache/apk/*

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
