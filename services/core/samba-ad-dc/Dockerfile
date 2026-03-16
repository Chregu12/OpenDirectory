FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    samba samba-ad-dc samba-dsdb-modules samba-vfs-modules \
    winbind libnss-winbind libpam-winbind \
    krb5-user krb5-config libkrb5-dev \
    dnsutils net-tools supervisor \
    curl gnupg2 \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js 18
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# Create log directories
RUN mkdir -p /var/log/samba /var/log/opendirectory

WORKDIR /app

COPY package.json .
RUN npm install --production

COPY src/ src/
COPY scripts/ scripts/

RUN chmod +x scripts/*.sh

EXPOSE 3008 389 636 88 464 135 3268 445

CMD ["supervisord", "-c", "/app/scripts/supervisord.conf"]
