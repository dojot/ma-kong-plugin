#!/bin/bash
set -e

###### Variables

KONG_HOST="localhost"
KONG_PORT=8001

KERBEROS_HOST="kerberos"
KERBEROS_PORT=8080

###### Registering APIs

# RegisterComponent
(curl http://${KONG_HOST}:${KONG_PORT}/apis -s -S -X POST \
    --header "Content-Type: application/json" \
    -d @- | python -m json.tool) <<PAYLOAD
{
    "name": "kerberos_registerComponent",
    "uris": "/kerberos/registerComponent",
    "strip_uri": true,
    "upstream_url": "http://${KERBEROS_HOST}:${KERBEROS_PORT}/kerberosintegration/rest/registry/registerComponent"
}
PAYLOAD

# UnegisterComponent
(curl http://${KONG_HOST}:${KONG_PORT}/apis -s -S -X POST \
    --header "Content-Type: application/json" \
    -d @- | python -m json.tool) <<PAYLOAD
{
    "name": "kerberos_unregisterComponent",
    "uris": "/kerberos/unregisterComponent",
    "strip_uri": true,
    "upstream_url": "http://${KERBEROS_HOST}:${KERBEROS_PORT}/kerberosintegration/rest/registry/unregisterComponent"
}
PAYLOAD

# RequestAS
(curl http://${KONG_HOST}:${KONG_PORT}/apis -s -S -X POST \
    --header "Content-Type: application/json" \
    -d @- | python -m json.tool) <<PAYLOAD
{
    "name": "kerberos_requestAS",
    "uris": "/kerberos/requestAS",
    "strip_uri": true,
    "upstream_url": "http://${KERBEROS_HOST}:${KERBEROS_PORT}/kerberosintegration/rest/protocol/requestAS"
}
PAYLOAD

# RequestAP
(curl http://${KONG_HOST}:${KONG_PORT}/apis -s -S -X POST \
    --header "Content-Type: application/json" \
    -d @- | python -m json.tool) <<PAYLOAD
{
    "name": "kerberos_requestAP",
    "uris": "/kerberos/requestAP",
    "strip_uri": true,
    "upstream_url": "http://${KERBEROS_HOST}:${KERBEROS_PORT}/kerberosintegration/rest/protocol/requestAP"
}
PAYLOAD

###### Configuring plugin

# RegisterComponent
curl -i -X POST \
    --url http://${KONG_HOST}:${KONG_PORT}/apis/kerberos_registerComponent/plugins/ \
    --data 'name=mutualauthentication' \
    --data "config.kerberos_url=http://${KERBEROS_HOST}:${KERBEROS_PORT}"

# UnegisterComponent
curl -i -X POST \
    --url http://${KONG_HOST}:${KONG_PORT}/apis/kerberos_unregisterComponent/plugins/ \
    --data 'name=mutualauthentication' \
    --data "config.kerberos_url=http://${KERBEROS_HOST}:${KERBEROS_PORT}"

# RequestAS
curl -i -X POST \
    --url http://${KONG_HOST}:${KONG_PORT}/apis/kerberos_requestAS/plugins/ \
    --data 'name=mutualauthentication' \
    --data "config.kerberos_url=http://${KERBEROS_HOST}:${KERBEROS_PORT}"

# RequestAP
curl -i -X POST \
    --url http://${KONG_HOST}:${KONG_PORT}/apis/kerberos_requestAP/plugins/ \
    --data 'name=mutualauthentication' \
    --data "config.kerberos_url=http://${KERBEROS_HOST}:${KERBEROS_PORT}"
