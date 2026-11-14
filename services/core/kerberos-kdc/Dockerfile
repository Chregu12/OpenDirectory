FROM node:20-bookworm-slim

RUN apt-get update && apt-get install -y \
    krb5-kdc \
    krb5-admin-server \
    krb5-user \
    ldap-utils \
    python3 \
    python3-pip \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# The entrypoint generates the Kerberos configuration from environment values.
COPY scripts/ /app/scripts/

# Install Node.js admin API wrapper
COPY package.json ./
RUN npm install --omit=dev --ignore-scripts --no-audit --no-fund

COPY src/ ./src/

EXPOSE 88/tcp 88/udp 749/tcp 3013/tcp

COPY scripts/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]
