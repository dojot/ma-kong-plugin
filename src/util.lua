local _M = {}

local json = require "cjson"

function _M.hex_dump(str)
    local len = string.len(str)
    local hex = ""

    for i = 1, len do
        local ord = string.byte( str, i )
        hex = hex .. string.format( "%02x", ord )
    end

    return hex
end

function _M.transform_json_body(body, add_table)
    local parameters = {}
    local content_length = (body and #body) or 0
    if content_length > 0 then
        parameters = json.decode(body)
    end
    if not parameters and content_length > 0 then
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
    return true, json.encode(parameters)
end

return _M
