local _M = {}

local find = string.find
local lower = string.lower

local json = require "json"
local util = require "kong.plugins.mutualauthentication.util"
local req_get_body_data = ngx.req.get_body_data

function string.fromhex(str)
    return (str:gsub('..', function (cc)
        return string.char(tonumber(cc, 16))
    end))
end

local function is_json_body(content_type)
    if content_type == nil then
        return nil
    end
    return find(lower(content_type), "application/json", nil, true)
end

local function getSessionInfo()
    local body = req_get_body_data()
    local body_json = json.decode(body)
    local sessionId = body_json["sessionId"]
    local transactionId = body_json["transactionId"]

    encodedString = string.fromhex(sessionId)
    encodedString = encodedString .. string.fromhex(transactionId)

    return encodedString
end

local function modifyRegisterComponent(conf, response_body_json)
    local request_body = req_get_body_data()
    local request_body_json = json.decode(request_body)
    local app_id = request_body_json["id"]
    local app_key = request_body_json["key"]

    response_body_json["appId"] = app_id
    response_body_json["appKey"] = app_key
    response_body_string = json.encode(response_body_json)

    ngx.header["Content-Length"] = #response_body_string
    ngx.arg[1] = response_body_string
end

local function modifyRequestAP(conf, response_body_json)
    -- Inserts sessionId and transactionId
    kerberosReply = response_body_json["kerberosReply"] -- Get "kerberosReply" value
    kerberosReply = string.fromhex(kerberosReply)

    ngx.arg[1] = kerberosReply
end

local function modifyRequestAS(conf, response_body_json)
    -- Inserts sessionId and transactionId
    kerberosReply = response_body_json["kerberosReply"] -- Get "kerberosReply" value
    kerberosReply = string.fromhex(kerberosReply)

    local session_info = getSessionInfo()
    ngx.arg[1] = session_info .. kerberosReply
end

function _M.run(conf)
    -- Decide if request is:
    -- --registerComponent -> send back appId and appKey
    -- --requestAS -> append sessionId, transactionId and kerberosReply
    -- --requestAP -> send kerberosReply only

    request_uri = ngx.var.request_uri

    local chunk, eof = ngx.arg[1], ngx.arg[2]
    if eof then
        if is_json_body(ngx.header["content-type"]) ~= nil and ngx.ctx.buffer ~= nil then
            local response_body_json = json.decode(ngx.ctx.buffer)
            if response_body_json == nil then
                return
            end

            if(string.match(request_uri, "unregisterComponent")) then

            elseif(string.match(request_uri, "registerComponent")) then
                modifyRegisterComponent(conf, response_body_json)

            elseif(string.match(request_uri, "requestAS")) then
                modifyRequestAS(conf, response_body_json)

            elseif(string.match(request_uri, "requestAP")) then
                modifyRequestAP(conf, response_body_json)

            end
        end
    else
        if ngx.ctx.buffer ~= nil and chunk ~= nil then
            ngx.ctx.buffer = ngx.ctx.buffer .. chunk
        end
        ngx.arg[1] = nil
    end
end

return _M
