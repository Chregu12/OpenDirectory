#!/bin/bash
set -e

REALM="${KRB5_REALM:-OPENDIRECTORY.LOCAL}"
KDC_HOST="${KDC_HOST:-localhost}"
ADMIN_PASSWORD="${KRB5_ADMIN_PASSWORD:-changeme}"
DB_PASSWORD="${KRB5_DB_PASSWORD:-changeme}"

echo "=== Configuring Kerberos KDC ==="
echo "Realm: $REALM"

# Write krb5.conf
cat > /etc/krb5.conf << EOF
[libdefaults]
    default_realm = ${REALM}
    dns_lookup_realm = false
    dns_lookup_kdc = false
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true

[realms]
    ${REALM} = {
        kdc = ${KDC_HOST}:88
        admin_server = ${KDC_HOST}:749
    }

[domain_realm]
    .opendirectory.local = ${REALM}
    opendirectory.local = ${REALM}
EOF

# Write kdc.conf
mkdir -p /etc/krb5kdc
cat > /etc/krb5kdc/kdc.conf << EOF
[kdcdefaults]
    kdc_ports = 88
    kdc_tcp_ports = 88

[realms]
    ${REALM} = {
        database_name = /var/lib/krb5kdc/principal
        admin_keytab = /etc/krb5kdc/kadm5.keytab
        acl_file = /etc/krb5kdc/kadm5.acl
        key_stash_file = /etc/krb5kdc/stash
        kdc_ports = 88
        max_life = 10h 0m 0s
        max_renewable_life = 7d 0h 0m 0s
        master_key_type = aes256-cts
        supported_enctypes = aes256-cts:normal aes128-cts:normal
    }
EOF

# Write ACL file
cat > /etc/krb5kdc/kadm5.acl << EOF
*/admin@${REALM}    *
EOF

# Initialize KDB if not already done
if [ ! -f /var/lib/krb5kdc/principal ]; then
    echo "Initializing Kerberos database..."
    echo -e "${DB_PASSWORD}\n${DB_PASSWORD}" | kdb5_util create -s -r "${REALM}"

    # Create admin principal
    kadmin.local -q "addprinc -pw ${ADMIN_PASSWORD} admin/admin@${REALM}"

    # Create host principal
    kadmin.local -q "addprinc -randkey host/${KDC_HOST}@${REALM}"

    # Create HTTP service principal (for SPNEGO/Kerberos SSO)
    kadmin.local -q "addprinc -randkey HTTP/${KDC_HOST}@${REALM}"

    # Create LDAP service principal
    kadmin.local -q "addprinc -randkey ldap/${KDC_HOST}@${REALM}"

    echo "Kerberos database initialized."
fi

# Start KDC and admin server
krb5kdc -P /var/run/krb5kdc.pid
kadmind -P /var/run/kadmind.pid

echo "KDC and kadmind started."

# Start the REST admin API
node /app/src/index.js &

# Keep container running
tail -f /var/log/syslog 2>/dev/null || tail -f /dev/null
