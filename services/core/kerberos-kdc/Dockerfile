FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    krb5-kdc \
    krb5-admin-server \
    krb5-user \
    ldap-utils \
    python3 \
    python3-pip \
    curl \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy configuration templates
COPY config/ /etc/krb5/templates/
COPY scripts/ /app/scripts/

# Install Node.js admin API wrapper
COPY package.json ./
RUN npm install --production

COPY src/ ./src/

EXPOSE 88/tcp 88/udp 749/tcp 3013/tcp

COPY scripts/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]
