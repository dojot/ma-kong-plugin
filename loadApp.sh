# RegisterComponent
(curl http://localhost:8001/apis -s -S -X POST \
    --header "Content-Type: application/json" \
    -d @- | python -m json.tool) <<PAYLOAD
{
    "name": "kerberos_loadApp",
    "uris": "/kerberos/loadApp",
    "strip_uri": true,
    "upstream_url": "http://kerberos:8080/kerberosintegration/rest/health/status"
}
PAYLOAD

# Read app list file
export IFS=";"
APP_ID_LIST=''
APP_KEY_LIST=''
while read -r APP_ID APP_KEY ; do
    APP_ID_LIST="$APP_ID_LIST,$APP_ID"
    APP_KEY_LIST="$APP_KEY_LIST,$APP_KEY"
done <<< "$(grep -v '^#' app_list.csv)"
APP_ID_LIST=${APP_ID_LIST:1}
APP_KEY_LIST=${APP_KEY_LIST:1}

curl -i -X POST \
    --url http://localhost:8001/apis/kerberos_loadApp/plugins/ \
    --data 'name=mutualauthentication' \
    --data 'config.kerberos_url=http://kerberos:8080' \
    --data "config.app_id=$APP_ID_LIST" \
    --data "config.app_key=$APP_KEY_LIST"

curl http://localhost:8000/kerberos/loadApp -s -S -X GET
