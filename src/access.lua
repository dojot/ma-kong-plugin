local _M = {}

local req_get_headers = ngx.req.get_headers
local pargs = ngx.req.get_post_args
local req_get_headers = ngx.req.get_headers
local body = ngx.req.read_body
local string_find = string.find
local pl_stringx = require "pl.stringx"
local responses = require "kong.tools.responses"
local socket = require "socket"
local http = require "socket.http"
local ltn12 = require "ltn12"
local lower = string.lower


local handshake = require "kong.plugins.mutualauthentication.handshake"
local util = require "kong.plugins.mutualauthentication.util"

local CONTENT_TYPE = "content-type"
local MA_SESSION_ID = "ma-session-id"
local MA_SESSION_ID_SIZE = 64

local function get_content_type(content_type)
  if content_type == nil then
    return
  end
  if string_find(content_type:lower(), "application/json", nil, true) then
    return "json"
  end
end

local function validate_ma_session_id()
    -- Get ma-session-id
    -- Get session information from Kerberos
    -- If session information is "KERBEROS_COMPLETED", forward request
    -- Else, return Not Authorized

    local ma_session_id = req_get_headers()[MA_SESSION_ID]
    if ma_session_id == nil then
        -- Request doesn't MA_SESSION_ID. Return Not Authorized.
        return responses.send(401)
    end

    -- Format ma_session_id
    if #ma_session_id ~= MA_SESSION_ID_SIZE then
        return responses.send(400, "Invalid ma-session-id size")
    end

    local session_id = string.sub(ma_session_id, 1, 32)
    local transaction_id = string.sub(ma_session_id, 33, 64)
    ma_session_id = session_id .. " - " .. transaction_id

    --local request_body = "{\"sessionId\":\"" .. ma_session_id .. "\"}"
    local request_url = "http://kerberos:8080/kerberosintegration/rest/registry/session/"
    request_url = request_url .. ma_session_id
    local response_body = { }
	local res, code, response_headers, status = http.request
	{
	    url = request_url,
	    method = "GET",
        sink = ltn12.sink.table(response_body),
	}
	util.printResponse(res, code, response_headers, status, source, sink, response_body)

    if code ~= 200 then
        return responses.send(401)
    end

    local response_string = response_body[1]
    local response_json = json.decode(response_string)
    if response_json == nil or response_json["result"] == nil then
        return responses.send(401)
    end

    if lower(response_json["result"]) ~= "kerberos_completed" then
        return responses.send(401)
    end

end

function _M.run(conf)
    local content_type_value = req_get_headers()[CONTENT_TYPE]
    local content_type = get_content_type(content_type_value)

    -- Obtem o prefixo usado no endereço (apenas para log)
    local request_uri = ngx.var.request_uri

    -- Decide if request is:
    -- --registerComponent
    -- --unregisterComponent
    -- --requestAS
    -- --requestAP

    if(string.match(request_uri, "unregisterComponent")) then
        handshake.unregisterComponent(conf)

    elseif(string.match(request_uri, "registerComponent")) then
        handshake.registerComponent(conf)

    elseif(string.match(request_uri, "requestAS")) then
        handshake.requestAS(conf)

    elseif(string.match(request_uri, "requestAP")) then
        handshake.requestAP(conf)

    elseif(string.match(request_uri, "loadApp")) then
        handshake.loadApp(conf)

    else
        -- If request is not related to mutual authentication, a Kerberos session
        -- validation will be performed instead.

        validate_ma_session_id()
    end
end

return _M
