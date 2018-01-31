local _M = {}

-- 3rd party
local responses = require "kong.tools.responses"
local http = require "socket.http"
local ltn12 = require "ltn12"
local jsonHandler = require "cjson"

-- internal
local handshake = require "kong.plugins.mutualauthentication.handshake"
local secureChannel = require "kong.plugins.mutualauthentication.secure_channel"

-- constants
local CONTENT_TYPE = "content-type"
local MA_SESSION_ID = "ma-session-id"
local MA_SESSION_ID_SIZE = 64

local function perform_mutual_authentication(maSessionId, kerberosUrl)
    -- Check ma-session-id
    -- Get session information from Kerberos
    -- If session information is "KERBEROS_COMPLETED", forward request
    -- Else, return Not Authorized    

    -- check mutual authentication session id lenght
    if #maSessionId ~= MA_SESSION_ID_SIZE then
        return ngx.HTTP_BAD_REQUEST,
               "Invalid \"" .. MA_SESSION_ID .. "\" size"
    end

    -- format the request
    local requestUrl = kerberosUrl ..
                       "/kerberosintegration/rest/registry/session/" ..
                       string.sub(maSessionId, 1, 32) ..
                       " - " ..
                       string.sub(maSessionId, 33, 64)

    -- send the request
    local responseBody = { }
    local res, code, responseHeaders, status = http.request
    {
        url = requestUrl,
        method = "GET",
        sink = ltn12.sink.table(responseBody),
    }

    -- request error checking
    if (not res) then
        ngx.log(ngx.ERR,
                "Failed on request session information. Error: ",
                code)
        return ngx.HTTP_INTERNAL_SERVER_ERROR, "internal error"
    end

    -- check request response
    if code ~= ngx.HTTP_OK then
        local error = ngx.HTTP_INTERNAL_SERVER_ERROR
        local errorMsg = "internal error"
        if code == ngx.HTTP_NOT_FOUND then
            error = ngx.HTTP_UNAUTHORIZED
            errorMsg = "Session expired"
        end
        ngx.log(ngx.ERR,
                "Failed on request session information. Error: ",
                code,
                ".",
                status)
        return error, errorMsg
    end

    if not responseBody[1] then
        ngx.log(ngx.ERR, "Response body is nil on consult session information")
        return ngx.HTTP_INTERNAL_SERVER_ERROR, "internal error"
    end

    -- response treatment
    local responseJson = jsonHandler.decode(responseBody[1])
    if (not responseJson) or (not responseJson["result"]) then
        ngx.log(ngx.ERR, "Unexpected kerberos response format")
        return ngx.HTTP_INTERNAL_SERVER_ERROR, "internal error"
    end

    if responseJson["result"]:lower() ~= "kerberos_completed" then
        ngx.log(ngx.ERR, "unexpected kerberos auth state: ", responseJson["result"])
        return ngx.HTTP_INTERNAL_SERVER_ERROR, "internal error"
    end

    return ngx.HTTP_OK, ""
end

local function perform_secure_channel(maSessionId)
    
    ngx.req.read_body()
    local bodyData = ngx.req.get_body_data()
    if not bodyData then
        -- there is not body data, so is not necessary decrypt it
        return true
    end

    local ok, decryptedContent = secureChannel.decrypt_from_component(maSessionId, bodyData)
    if ok then
        -- replace the content with the decrypted original content
        ngx.req.set_body_data(decryptedContent)
        ngx.log(ngx.DEBUG, "decrypted content: ", decryptedContent)
    else
        ngx.log(ngx.ERR, "Some problem on decrypt content")
        return false
    end

    return true
end

function _M.run(conf)

    local requestUri = ngx.var.request_uri
    
    if(requestUri == handshake.ENDPOINT_UNREGISTER_COMPONENT) then
        handshake.unregisterComponent(conf)
    elseif(requestUri == handshake.ENDPOINT_REGISTER_COMPONENT) then
        handshake.registerComponent(conf)
    elseif(requestUri == handshake.ENDPOINT_REQUEST_AS) then
        handshake.requestAS(conf)
    elseif(requestUri == handshake.ENDPOINT_REQUEST_AP) then
        handshake.requestAP(conf)
    elseif(requestUri == handshake.ENDPOINT_LOAD_APP) then
        handshake.loadApp(conf)
    else
        -- If request is not related to mutual authentication, a Kerberos session
        -- validation will be performed instead.

        local maSessionId = ngx.req.get_headers()[MA_SESSION_ID]
        if not maSessionId then
            -- Request doesn't MA_SESSION_ID. Return Not Authorized.
            return responses.send_HTTP_UNAUTHORIZED(
                    "missing \"" .. MA_SESSION_ID .. "\" header's attribute")
        end

        local result, errMsg = perform_mutual_authentication(maSessionId,
                                                             conf.kerberos_url)
        if result ~= ngx.HTTP_OK then
            ngx.log(ngx.ERR, "Mutual authentication error: ", result, ". Msg: ", errMsg)
            responses.send(result, errMsg)
            return
        end

        ngx.log(ngx.DEBUG, "Mutual authentication performed successfully")
        if not conf.secure_channel_enabled then
             return
         end
        
        local result = perform_secure_channel(maSessionId)
        if not result then
            ngx.log(ngx.ERR, "Failed on perform secure channel")
            responses.send_HTTP_INTERNAL_SERVER_ERROR()
        end

    end
end

return _M
