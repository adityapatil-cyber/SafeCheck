FROM node:22-bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends clamav clamav-daemon clamav-freshclam ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Configure ClamAV daemon with strict archive & resource limits
RUN mkdir -p /var/run/clamav /var/lib/clamav && \
    chown -R clamav:clamav /var/run/clamav /var/lib/clamav && \
    sed -i 's/^#LocalSocket /LocalSocket /' /etc/clamav/clamd.conf || true && \
    echo "FixStaleSocket true" >> /etc/clamav/clamd.conf && \
    echo "MaxFileSize 30M" >> /etc/clamav/clamd.conf && \
    echo "MaxScanSize 100M" >> /etc/clamav/clamd.conf && \
    echo "MaxRecursion 10" >> /etc/clamav/clamd.conf && \
    echo "MaxFiles 2000" >> /etc/clamav/clamd.conf && \
    echo "ScanArchive yes" >> /etc/clamav/clamd.conf && \
    freshclam || true

WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev
COPY server.mjs ./

ENV NODE_ENV=production
ENV PORT=8080

EXPOSE 8080

CMD ["sh", "-c", "freshclam --quiet || true; clamd && for i in $(seq 1 30); do clamdscan --ping 1 >/dev/null 2>&1 && break; sleep 1; done && node server.mjs"]
