local _M = {}

-- 3rd party
local json = require "cjson"
local uuid = require "uuid"
local http = require "socket.http"
local responses = require "kong.tools.responses"

-- internal
local util = require "kong.plugins.mutualauthentication.util"

-- consts
local CONTENT_LENGTH = "Content-Length"
local CONTENT_TYPE = "Content-Type"

-- public variables
_M.ENDPOINT_UNREGISTER_COMPONENT = "/kerberos/unregisterComponent"
_M.ENDPOINT_REGISTER_COMPONENT = "/kerberos/registerComponent"
_M.ENDPOINT_REQUEST_AS = "/kerberos/requestAS"
_M.ENDPOINT_REQUEST_AP = "/kerberos/requestAP"
_M.ENDPOINT_LOAD_APP = "/kerberos/loadApp"

function unregisterComponent(conf)
end

function _M.loadApp(conf)
    local app_id = conf.app_id
    local app_key = conf.app_key

    if #app_id ~= #app_key then
        ngx.log(ngx.ERR, "Failed on load application. Number of app_id and app_key does not match")
        responses.send_HTTP_BAD_REQUEST()
        return
    end

    for i=1, #app_id do
        local component_table = {}
        component_table["id"] = app_id[i]
        component_table["key"] = app_key[i]

        local isOk, request = util.transform_json_body("", component_table)
        if not isOk then
            ngx.log(ngx.ERR, "Failed on transform body request on loadApp")
            responses.send_HTTP_BAD_REQUEST()
            return
        end

        local response_body = { }

	    local res, code, response_headers, status = http.request {
	        url = conf.kerberos_url .. "/kerberosintegration/rest/registry/registerComponent",
	        method = "POST",
		    headers = {
		        [CONTENT_TYPE] = "application/json",
                [CONTENT_LENGTH] = request:len()
		    },
            source = ltn12.source.string(request),
            sink = ltn12.sink.table(response_body)
	    }

        -- request error checking
        if (not res) then
            ngx.log(ngx.ERR, "Failed on load application. Error: ", code)
            responses.send_HTTP_INTERNAL_SERVER_ERROR(
                "missing \"" .. MA_SESSION_ID .. "\" header's attribute")
            return
        end

        --todo: can we improve the error handling here? kerberos API does
        --      not have error codes, so for now we will use a generic error

        -- check request response
        if code ~= ngx.HTTP_OK then
            ngx.log(ngx.ERR,
                    "Failed to load application. Error: ",
                    code,
                    ".",
                    status)
            responses.send_HTTP_CONFLICT()
            return
        end

    end -- for
end

function _M.registerComponent(conf)

    uuid.randomseed(socket.gettime()*10000)
    -- Generates application id
    local appId = uuid()
    appId = string.gsub(appId, "-", "")
    appId = string.sub(appId, -16)

    -- Generates application key
    local appKey = uuid()
    appKey = string.gsub(appKey, "-", "")

    local component_table = {}
    component_table["id"] = appId
    component_table["key"] = appKey

    -- Call ngx.req.read_body to read the request body first
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local content_length = (body and #body) or 0

    local isOk, body = util.transform_json_body(body, component_table)
    if not isOk then
        ngx.log(ngx.ERR, "Failed to transform body request on registerComponent")
        responses.send_HTTP_INTERNAL_SERVER_ERROR()
        return
    end

    ngx.req.set_body_data(body)
    ngx.req.set_header(CONTENT_LENGTH, #body)

end

function _M.requestAS(conf)

    -- we need to call ngx.req.read_body to read the request body first
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local content_length = (body and #body) or 0
    if not body then
        ngx.log(ngx.ERR, "Empty body on requestAS")
        responses.send_HTTP_BAD_REQUEST()
        return
    end

    -- Generates sessionId
    local sessionId = uuid()
    sessionId = string.gsub(sessionId, "-", "")

    -- Generates transactionId
    local transactionId = uuid()
    transactionId = string.gsub(transactionId, "-", "")

    ngx.log(ngx.DEBUG, "sessionId: ", sessionId)
    ngx.log(ngx.DEBUG, "transaction id: ", transactionId)

    -- Registers session
    local payload = [[ {"sessionId":"]] .. sessionId .. [[","transactionId":"]]
        .. transactionId .. [["} ]]
    local response_body = { }

    local res, code, response_headers, status = http.request {
        url = conf.kerberos_url .. '/kerberosintegration/rest/registry/registerSession',
	    method = "POST",
		headers = {
            [CONTENT_TYPE] = "application/json",
            [CONTENT_LENGTH] = payload:len()
		},
        source = ltn12.source.string(payload),
        sink = ltn12.sink.table(response_body),
    }

    if not res then
        ngx.log(ngx.ERR, "Failed to register sesssion for sessionId: ", sessionId,
                        " transaction id: ", transactionId,
                         " error: ", code)
        return false
    end

    --todo: can we improve the error handling here? kerberos API does
    --      not have error codes, so for now we will use a generic error

    -- check request response
    if code ~= ngx.HTTP_OK then
        ngx.log(ngx.ERR, "Failed to register session. Error: ", code, ".", status)
        responses.send_HTTP_CONFLICT()
        return
    end
    
    -- Inserts sessionId and transactionId into original request
    local sessionTable = {}
    sessionTable["sessionId"] = sessionId
    sessionTable["transactionId"] = transactionId
    sessionTable["request"] = util.hex_dump(body)
    local newContent = json.encode(sessionTable)

    -- replace the original request's content with the new one
    ngx.req.set_body_data(newContent)
    ngx.req.set_header(CONTENT_LENGTH, #newContent)
    ngx.req.set_header(CONTENT_TYPE, "application/json")

    return
end

function _M.requestAP(conf)
    -- Call ngx.req.read_body to read the request body first
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local content_length = (body and #body) or 0
    if not body then
        ngx.log(ngx.ERR, "Empty body on requestAP")
        responses.send_HTTP_BAD_REQUEST()
        return
    end
    local body_string = util.hex_dump(body)

    local sessionId = string.sub(body_string, 1, 32)
    local transactionId = string.sub(body_string, 33, 64)
    local request = string.sub(body_string, 65)

    local requestTable = {}
    requestTable["sessionId"] = sessionId
    requestTable["transactionId"] = transactionId
    requestTable["request"] = request

    local newContent = json.encode(requestTable)

    ngx.req.set_body_data(newContent)
    ngx.req.set_header(CONTENT_LENGTH, #newContent)
    ngx.req.set_header(CONTENT_TYPE, "application/json")

end

return _M
