# ── Stage 1: Build Samba from source ─────────────────────────────────────────
FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    # Build toolchain
    build-essential pkg-config python3 python3-dev \
    python3-cryptography python3-dnspython python3-markdown \
    python3-iso8601 python3-pyasn1 python3-setuptools \
    # TLS / crypto
    libgnutls28-dev gnutls-bin libtasn1-6-dev \
    # LDAP
    libldap2-dev libsasl2-dev \
    # Filesystem & ACL
    libacl1-dev libattr1-dev libblkid-dev \
    # Misc build deps
    libreadline-dev libpopt-dev libjansson-dev \
    libarchive-dev libgpgme-dev \
    libcups2-dev libpam0g-dev \
    libaio-dev zlib1g-dev \
    # Parser tools
    bison flex perl \
    # Downloader
    wget \
    && rm -rf /var/lib/apt/lists/*

ARG SAMBA_VERSION=4.24.0

RUN wget -q "https://download.samba.org/pub/samba/stable/samba-${SAMBA_VERSION}.tar.gz" \
    && tar xzf "samba-${SAMBA_VERSION}.tar.gz" \
    && cd "samba-${SAMBA_VERSION}" \
    && ./configure \
        --prefix=/usr/local/samba \
        --sysconfdir=/etc/samba \
        --localstatedir=/var \
        --with-privatedir=/var/lib/samba/private \
        --with-statedir=/var/lib/samba \
        --with-cachedir=/var/cache/samba \
        --with-logfilebase=/var/log/samba \
        --with-lockdir=/var/run/samba \
        --with-piddir=/var/run/samba \
        --enable-gnutls \
        --without-cluster-support \
        --bundled-libraries=ALL \
    && make -j"$(nproc)" \
    && make install \
    && cd .. \
    && rm -rf "samba-${SAMBA_VERSION}" "samba-${SAMBA_VERSION}.tar.gz"

# ── Stage 2: Runtime image ────────────────────────────────────────────────────
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Runtime libraries (Samba + Kerberos + utilities)
RUN apt-get update && apt-get install -y \
    python3 python3-dnspython python3-cryptography \
    libgnutls30 libldap-2.5-0 libsasl2-2 \
    libacl1 libattr1 libreadline8 libpopt0 \
    libjansson4 libarchive13 libgpgme11 \
    libcups2 libpam0g \
    krb5-user krb5-config \
    dnsutils net-tools openssl \
    supervisor curl \
    && rm -rf /var/lib/apt/lists/*

# Copy compiled Samba from builder
COPY --from=builder /usr/local/samba /usr/local/samba

ENV PATH="/usr/local/samba/bin:/usr/local/samba/sbin:${PATH}"
ENV LD_LIBRARY_PATH="/usr/local/samba/lib:${LD_LIBRARY_PATH}"

# Symlinks so existing code using /usr/bin/samba-tool and /usr/sbin/samba still works
RUN ln -s /usr/local/samba/bin/samba-tool  /usr/bin/samba-tool  \
    && ln -s /usr/local/samba/sbin/samba   /usr/sbin/samba      \
    && ln -s /usr/local/samba/bin/smbclient /usr/bin/smbclient

# Install Node.js 20 LTS
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/log/samba /var/log/opendirectory /var/run/samba

WORKDIR /app

COPY package.json .
RUN npm install --production

COPY src/ src/
COPY scripts/ scripts/

RUN chmod +x scripts/*.sh

# Ports: REST API, LDAP, LDAPS, Kerberos, Kerberos/pw, DCOM, Global Catalog, GC SSL, SMB
EXPOSE 3010 389 636 88 464 135 3268 3269 445

CMD ["supervisord", "-c", "/app/scripts/supervisord.conf"]
