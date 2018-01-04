local _M = {}

local json = require "json"

function _M.printToFile(line, txt)
	local s = "echo \"Linha " .. line .. " - " .. txt .."\"  >> /tmp/mutualauthentication.log"
	os.execute(s)
end

function _M.printResponse(res, code, response_headers, status, source, sink, response_body)
    if(res ~= nil) then
        _M.printToFile(0, "res: " .. res)
    end
    if(code ~= nil) then
        _M.printToFile(0, "code: " .. code)
    end
    if(response_headers ~= nil) then
        table.foreach(response_headers, print)
    end
    if(status ~= nil) then
        _M.printToFile(0, "status: " .. status)
    end
    if(source ~= nil) then
        _M.printToFile(0, "source: " .. source)
    end
    if(sink ~= nil) then
        _M.printToFile(0, "sink: " .. sink)
    end
    print()
end

function _M.hex_dump(str)
    local len = string.len(str)
    local hex = ""

    for i = 1, len do
        local ord = string.byte( str, i )
        hex = hex .. string.format( "%02x", ord )
    end

    return hex
end

function _M.transform_json_body(conf, body, add_table)
    local parameters = {}
    local content_length = (body and #body) or 0
    if content_length > 0 then
        parameters = json.decode(body)
    end
    if parameters == nil and content_length > 0 then
        return false, nil
    end

    -- Adds parameters to json
    table.foreach(add_table,
        function(k, v)
            if not parameters[k] then
                parameters[k] = v
            end
        end
    )
    return json.encode(parameters)
end

return _M
