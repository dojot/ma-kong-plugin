local _M = {}

-- 3rd party
local json = require "cjson"

-- internal
local util = require "kong.plugins.mutualauthentication.util"
local secureChannel = require "kong.plugins.mutualauthentication.secure_channel"
local handshake = require "kong.plugins.mutualauthentication.handshake"

function string.fromhex(str)
    return (str:gsub('..', function (cc)
        return string.char(tonumber(cc, 16))
    end))
end

local function is_json_body(content_type)
    if (not content_type) or (content_type:lower() ~= "application/json") then
        return false
    end
    return true
end

local function getSessionInfo()
    local body = ngx.req.get_body_data()
    local body_json = json.decode(body)
    local sessionId = body_json["sessionId"]
    local transactionId = body_json["transactionId"]

    encodedString = string.fromhex(sessionId)
    encodedString = encodedString .. string.fromhex(transactionId)

    return encodedString
end

local function modifyRegisterComponent(conf)

    if (not is_json_body(ngx.header["content-type"])) or (not ngx.ctx.buffer) then
        return false
    end

    local response_body_json = json.decode(ngx.ctx.buffer)
    if not response_body_json then
        return false
    end

    local request_body = ngx.req.get_body_data()
    local request_body_json = json.decode(request_body)
    local app_id = request_body_json["id"]
    local app_key = request_body_json["key"]

    response_body_json["appId"] = app_id
    response_body_json["appKey"] = app_key
    response_body_string = json.encode(response_body_json)

    ngx.header["Content-Length"] = #response_body_string
    ngx.arg[1] = response_body_string
    return true
end

local function modifyRequestAS(conf)
    if (not is_json_body(ngx.header["content-type"])) or (not ngx.ctx.buffer) then
        return false
    end

    local response_body_json = json.decode(ngx.ctx.buffer)
    if not response_body_json then
        return false
    end

    -- Inserts sessionId and transactionId
    kerberosReply = response_body_json["kerberosReply"] -- Get "kerberosReply" value
    kerberosReply = string.fromhex(kerberosReply)

    local session_info = getSessionInfo()
    ngx.arg[1] = session_info .. kerberosReply
    return true
end

local function modifyRequestAP(conf)
    if (not is_json_body(ngx.header["content-type"])) or (not ngx.ctx.buffer) then
        return false
    end

    local response_body_json = json.decode(ngx.ctx.buffer)
    if not response_body_json then
        return false
    end

    -- Inserts sessionId and transactionId
    kerberosReply = response_body_json["kerberosReply"] -- Get "kerberosReply" value
    kerberosReply = string.fromhex(kerberosReply)

    ngx.arg[1] = kerberosReply
    return true
end

local function modifyOrdinaryReply(conf)

    -- if secure channel is not enabled we do not need to modify anything
    if not conf.secure_channel_enabled then
        return true
    end

    -- is there some content?
    if not ngx.ctx.buffer then
        return true
    end

    local ok, encryptedContent = secureChannel.encrypt_from_server(ngx.ctx.buffer)
    if ok then
        -- replace the reply with the encrypted version
        ngx.req.set_body_data(encryptedContent)
        ngx.arg[1] = encryptedContent

        ngx.log(ngx.DEBUG, "Message encrypted successfully.")
    else
        ngx.log(ngx.ERR, "failed to encrypt msg")
        return false
    end

    return true
end

function _M.run(conf)
    -- Decide if request is:
    -- --registerComponent -> send back appId and appKey
    -- --requestAS -> append sessionId, transactionId and kerberosReply
    -- --requestAP -> send kerberosReply only
    
    local chunk, eof = ngx.arg[1], ngx.arg[2]    
    if not eof then
        -- the reply's content is not complete yet
        -- we need to concatenate it into the buffer
        if ngx.ctx.buffer and chunk then
            ngx.ctx.buffer = ngx.ctx.buffer .. chunk
        end
        ngx.arg[1] = nil
    else
        -- alright, now we have all the reply's content
        -- let's process it

        local requestUri = ngx.var.request_uri
        ngx.log(ngx.DEBUG, "body filter: ", requestUri)

        -- todo: write functions documentation

        local isOk = false
        
        -- todo: is necessary modify unregister component?
        if(requestUri == handshake.ENDPOINT_REGISTER_COMPONENT) then
            isOk = modifyRegisterComponent(conf)
        elseif(requestUri == handshake.ENDPOINT_REQUEST_AS) then
            isOk = modifyRequestAS(conf)
        elseif(requestUri == handshake.ENDPOINT_REQUEST_AP) then
            isOk = modifyRequestAP(conf)
        else
            isOk = modifyOrdinaryReply(conf)
        end
    
        if not isOk then
            -- ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
            return ngx.ERROR
        end
    end
end

return _M
