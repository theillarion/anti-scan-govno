FROM python:3.13-slim-trixie
RUN apt-get update && apt-get install -y --no-install-recommends nftables tzdata libcap2-bin && rm -rf /var/lib/apt/lists/*
COPY nftguard.py /usr/local/bin/nftguard
COPY nftguard-entrypoint.sh /usr/local/bin/nftguard-entrypoint
HEALTHCHECK --interval=5m --timeout=15s --start-period=5m --retries=3 CMD ["python3", "/usr/local/bin/nftguard", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/nftguard-entrypoint"]
