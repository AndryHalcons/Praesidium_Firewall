#!/bin/bash
set -e

cd ../data/certs || exit 1

# =========================
# CA raíz - Generación
# =========================
openssl genrsa -out praesidium_root_ca.key 4096
openssl req -x509 -new -nodes -key praesidium_root_ca.key -sha256 -days 3650 \
  -out praesidium_root_ca.pem \
  -subj "/C=ES/O=Praesidium/OU=RootCA/CN=Praesidium Root CA"

# =========================
# CA intermedia - Generación
# =========================
openssl genrsa -out praesidium_intermediate_ca.key 4096
openssl req -new -key praesidium_intermediate_ca.key -out praesidium_intermediate_ca.csr \
  -subj "/C=ES/O=Praesidium/OU=IntermediateCA/CN=Praesidium Intermediate CA"

# =========================
# Extensiones para firmar como CA y servidor
# =========================
cat > ca_ext.cnf <<EOF
[ v3_ca ]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer

[ server_cert ]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
EOF

# =========================
# CA intermedia - Firma por la raíz
# =========================
openssl x509 -req -in praesidium_intermediate_ca.csr -CA praesidium_root_ca.pem -CAkey praesidium_root_ca.key \
  -CAcreateserial -out praesidium_intermediate_ca.pem -days 1825 -sha256 \
  -extfile ca_ext.cnf -extensions v3_ca

# =========================
# CA emisora - Generación
# =========================
openssl genrsa -out praesidium_issuer_ca.key 4096
openssl req -new -key praesidium_issuer_ca.key -out praesidium_issuer_ca.csr \
  -subj "/C=ES/O=Praesidium/OU=IssuingCA/CN=Praesidium Issuing CA"

# =========================
# CA emisora - Firma por la intermedia
# =========================
openssl x509 -req -in praesidium_issuer_ca.csr -CA praesidium_intermediate_ca.pem -CAkey praesidium_intermediate_ca.key \
  -CAcreateserial -out praesidium_issuer_ca.pem -days 1825 -sha256 \
  -extfile ca_ext.cnf -extensions v3_ca

# =========================
# CA para clientes - Generación
# =========================
openssl genrsa -out praesidium_client_ca.key 4096
openssl req -new -key praesidium_client_ca.key -out praesidium_client_ca.csr \
  -subj "/C=ES/O=Praesidium/OU=ClientCA/CN=Praesidium Client CA"

# =========================
# CA para clientes - Firma por la intermedia
# =========================
openssl x509 -req -in praesidium_client_ca.csr -CA praesidium_intermediate_ca.pem -CAkey praesidium_intermediate_ca.key \
  -CAcreateserial -out praesidium_client_ca.pem -days 1825 -sha256 \
  -extfile ca_ext.cnf -extensions v3_ca

# =========================
# Certificado de servidor - Generación
# =========================
openssl genrsa -out praesidium_server.key 4096
openssl req -new -key praesidium_server.key -out praesidium_server.csr \
  -subj "/C=ES/O=Praesidium/OU=Server/CN=server.praesidium.local"

# =========================
# Certificado de servidor - Firma por la emisora
# =========================
openssl x509 -req -in praesidium_server.csr -CA praesidium_issuer_ca.pem -CAkey praesidium_issuer_ca.key \
  -CAcreateserial -out praesidium_server.pem -days 825 -sha256 \
  -extfile ca_ext.cnf -extensions server_cert
