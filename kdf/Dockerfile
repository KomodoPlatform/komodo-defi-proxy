# Use the upstream KDF dev image as the base
FROM gleec/komodo-defi-framework:dev-latest

# Install troubleshooting tools: curl, netstat (net-tools) and pgrep (procps)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       curl \
        net-tools \
        netcat-openbsd \
        procps \
    && rm -rf /var/lib/apt/lists/*

# Keep the original entrypoint/cmd from the base image ("kdf") 