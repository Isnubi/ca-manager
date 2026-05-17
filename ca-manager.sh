#!/bin/bash

# ==========================================
# CONFIGURATION
# ==========================================
CA_DIR="/opt/private-ca"
CA_KEY="$CA_DIR/rootCA.key"
CA_CERT="$CA_DIR/rootCA.pem"
CRL_FILE="$CA_DIR/rootCA.crl"
DATABASE="$CA_DIR/index.txt"
SERIAL_FILE="$CA_DIR/serial"

# Certificate Validity
DAYS_VALID_ROOT=3650  # 10 years
DAYS_VALID_CERT=375   # ~1 year

# Subject (DN) Variables
SUBJ_C="FR"           # Country
SUBJ_ST="Ile-de-France"        # State
SUBJ_L="Alfortville"          # Locality
SUBJ_O="Homelab"      # Organization
SUBJ_OU="Services"    # Organizational Unit

# ==========================================
# INFRASTRUCTURE SETUP
# ==========================================
mkdir -p "$CA_DIR"
touch "$DATABASE"

case "$1" in
    init)
        echo "--- Initializing Private Root CA ---"
        echo 1000 > "$SERIAL_FILE"

        # Root CA Subject
        ROOT_SUBJ="/C=$SUBJ_C/ST=$SUBJ_ST/L=$SUBJ_L/O=$SUBJ_O/CN=$SUBJ_O Root CA"

        # Generate Root Key
        openssl genrsa -out "$CA_KEY" 4096

        # Generate Root Certificate
        openssl req -x509 -new -nodes -key "$CA_KEY" -sha256 -days $DAYS_VALID_ROOT \
            -out "$CA_CERT" -subj "$ROOT_SUBJ"

        # Create initial empty CRL
        openssl ca -gencrl -keyfile "$CA_KEY" -cert "$CA_CERT" -out "$CRL_FILE" -config <(echo "[ca]
default_ca = CA_default
[CA_default]
database = $DATABASE
serial = $SERIAL_FILE
default_md = sha256
default_crl_days = 365")

        echo "Done! Root CA initialized."
        echo "Root Subject: $ROOT_SUBJ"
        echo "--> IMPORTANT: Install '$CA_CERT' in your device's Trusted Root store."
        ;;

    issue)
        DOMAIN=$2
        if [ -z "$DOMAIN" ]; then echo "Usage: $0 issue <domain.local>"; exit 1; fi

        echo "--- Issuing Cert for: $DOMAIN ---"

        # Service Subject
        SERVICE_SUBJ="/C=$SUBJ_C/ST=$SUBJ_ST/L=$SUBJ_L/O=$SUBJ_O/OU=$SUBJ_OU/CN=$DOMAIN"

        # Generate Service Key
        openssl genrsa -out "$CA_DIR/$DOMAIN.key" 2048

        # Create SAN config (Required for modern browsers)
        EXT_FILE="$CA_DIR/$DOMAIN.ext"
        echo "authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = DNS:$DOMAIN" > "$EXT_FILE"

        # Create CSR
        openssl req -new -key "$CA_DIR/$DOMAIN.key" -out "$CA_DIR/$DOMAIN.csr" \
            -subj "$SERVICE_SUBJ"

        # Sign the cert
        openssl x509 -req -in "$CA_DIR/$DOMAIN.csr" -CA "$CA_CERT" -CAkey "$CA_KEY" \
            -CAcreateserial -out "$CA_DIR/$DOMAIN.crt" -days $DAYS_VALID_CERT -sha256 \
            -extfile "$EXT_FILE"

        # Record in index.txt for tracking
        SERIAL_VAL=$(openssl x509 -in "$CA_DIR/$DOMAIN.crt" -noout -serial | cut -d'=' -f2)
        echo "V $(date +%y%m%d%H%M%SZ)  $SERIAL_VAL unknown /CN=$DOMAIN" >> "$DATABASE"

        echo "Success! Issued $DOMAIN"
        ;;

    list)
        echo "--- Issued Certificates ---"
        printf "%-30s %-20s %-10s\n" "Domain (CN)" "Serial" "Status"
        echo "----------------------------------------------------------------------"
        while read -r status date serial junk cn; do
            stat="Valid"
            if [ "$status" == "R" ]; then stat="REVOKED"; fi
            printf "%-30s %-20s %-10s\n" "${cn#/CN=}" "$serial" "$stat"
        done < "$DATABASE"
        ;;

    show)
        DOMAIN=$2
        if [ ! -f "$CA_DIR/$DOMAIN.crt" ]; then echo "Error: Cert for $DOMAIN not found."; exit 1; fi

        echo "========================================================="
        echo "   COPY/PASTE DATA FOR: $DOMAIN"
        echo "========================================================="
        echo -e "\n--- CERTIFICATE ($DOMAIN.crt) ---"
        cat "$CA_DIR/$DOMAIN.crt"
        echo -e "\n--- PRIVATE KEY ($DOMAIN.key) ---"
        cat "$CA_DIR/$DOMAIN.key"
        echo -e "\n========================================================="
        ;;

    revoke)
        DOMAIN=$2
        if [ -z "$DOMAIN" ]; then echo "Usage: $0 revoke <domain.local>"; exit 1; fi

        if grep -q "/CN=$DOMAIN" "$DATABASE"; then
            # Use a more precise sed to replace only the 'V' at the start of the line for that domain
            # This ensures we don't break the tab-formatting OpenSSL expects
            sed -i "/\/CN=$DOMAIN$/s/^V/R/" "$DATABASE"

            # Create a minimal valid config for CRL generation
            # We add 'dir' and 'database' specifically
            CONF_FILE=$(mktemp)
            cat <<EOF > "$CONF_FILE"
[ ca ]
default_ca = CA_default
[ CA_default ]
database = $DATABASE
serial = $SERIAL_FILE
default_md = sha256
default_crl_days = 365
EOF

            openssl ca -gencrl -keyfile "$CA_KEY" -cert "$CA_CERT" -out "$CRL_FILE" -config "$CONF_FILE" -batch
            rm "$CONF_FILE"

            echo "Certificate for $DOMAIN has been marked as REVOKED."
        else
            echo "Error: Domain $DOMAIN not found in $DATABASE."
        fi
        ;;
    show-ca)
        echo "========================================================="
        echo "   COPY/PASTE DATA FOR CA CERTIFICATE"
        echo "========================================================="
        cat "$CA_CERT"
        echo -e "\n========================================================="
        ;;

    *)
        echo "Homelab CA Manager"
        echo "Usage: $0 {init|issue <domain>|list|show <domain>|revoke <domain>|show-ca}"
        exit 1
        ;;
esac
