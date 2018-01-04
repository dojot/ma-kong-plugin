#!/bin/bash
set -e

###### Registering APIs

# RegisterComponent
(curl http://localhost:8001/apis -s -S -X POST \
    --header "Content-Type: application/json" \
    -d @- | python -m json.tool) <<PAYLOAD
{
    "name": "kerberos_registerComponent",
    "uris": "/kerberos/registerComponent",
    "strip_uri": true,
    "upstream_url": "http://kerberos:8080/kerberosintegration/rest/registry/registerComponent"
}
PAYLOAD

# UnegisterComponent
(curl http://localhost:8001/apis -s -S -X POST \
    --header "Content-Type: application/json" \
    -d @- | python -m json.tool) <<PAYLOAD
{
    "name": "kerberos_unregisterComponent",
    "uris": "/kerberos/unregisterComponent",
    "strip_uri": true,
    "upstream_url": "http://kerberos:8080/kerberosintegration/rest/registry/unregisterComponent"
}
PAYLOAD

# RequestAS
(curl http://localhost:8001/apis -s -S -X POST \
    --header "Content-Type: application/json" \
    -d @- | python -m json.tool) <<PAYLOAD
{
    "name": "kerberos_requestAS",
    "uris": "/kerberos/requestAS",
    "strip_uri": true,
    "upstream_url": "http://kerberos:8080/kerberosintegration/rest/protocol/requestAS"
}
PAYLOAD

# RequestAP
(curl http://localhost:8001/apis -s -S -X POST \
    --header "Content-Type: application/json" \
    -d @- | python -m json.tool) <<PAYLOAD
{
    "name": "kerberos_requestAP",
    "uris": "/kerberos/requestAP",
    "strip_uri": true,
    "upstream_url": "http://kerberos:8080/kerberosintegration/rest/protocol/requestAP"
}
PAYLOAD

###### Configuring plugin


curl -i -X POST \
    --url http://localhost:8001/apis/kerberos_registerComponent/plugins/ \
    --data 'name=mutualauthentication' \
    --data 'config.kerberos_url="http://kerberos:8080/"'

curl -i -X POST \
    --url http://localhost:8001/apis/kerberos_unregisterComponent/plugins/ \
    --data 'name=mutualauthentication' \
    --data 'config.kerberos_url="http://kerberos:8080/"'

curl -i -X POST \
    --url http://localhost:8001/apis/kerberos_requestAS/plugins/ \
    --data 'name=mutualauthentication' \
    --data 'config.kerberos_url="http://kerberos:8080/"'

curl -i -X POST \
    --url http://localhost:8001/apis/kerberos_requestAP/plugins/ \
    --data 'name=mutualauthentication' \
    --data 'config.kerberos_url="http://kerberos:8080/"'
