local _M = {}

-- modules
local redis = require "resty.redis"
local jsonHandler = require "cjson"
local util = require "kong.plugins.mutualauthentication.util"
local aes = require "resty.aes"
local random = require "resty.random"
local str = require "resty.string"

-- crypto related
local ivLength = 12


function string.fromhex(str)
    return (str:gsub('..', function (cc)
        return string.char(tonumber(cc, 16))
    end))
end

--- Receives a sessionId (a string with 64 characters) and returns a string
-- with the format used in Redis 
-- example:
--   sessionId = "03fc33ccc8b74144c123779078bc73bab4917cf55bd64145c1ff7ba38a76ec18"
--   redis key = "cryptochannel.03fc33ccc8b74144c123779078bc73ba - b4917cf55bd64145c1ff7ba38a76ec18.A"
-- @param sessionId the session key target
-- @return the generated redis key
local function gen_redis_key(sessionId)
    sessionId = tostring(sessionId)
	local half = #sessionId/2
	return "cryptochannel." ..
			sessionId:sub(1, half) .. -- sessionId's first half
			" - " ..
			sessionId:sub(half + 1) .. -- sessionId's second half
			".A"
end

--- Retrieves session related parameters to secure channel
-- @param sessionId 
-- @return <bool, table>
-- bool: incates if the parameters have been retrieved or not
-- table: a table with the following parameters: (the values are just for reference)
--   - keyServerToComponent : "B0322F59D21D0EC6DF6F8219637B2ED2"
--   - keyComponentToServer : "40201344A1C9E7B1CFA973FDD78CA42B"
--   - ivServerToComponent : "59EE575C047109A54412244C"
--   - ivComponentToServer : "E0AAC38719644B69076B7D0D"
--   - tagLen : 128
--   - provider : "BC"
-- the table will be available only when the first returned value is true, otherwise
-- a nil value will be returned
-- @usage this function uses the ngx.ctx variables redisHost and redisPort
-- make sure it is configured properly before this function be called
local function retrieve_session_param(sessionId)

    local redisSessionKey = gen_redis_key(sessionId)

    local redisClient = redis:new()
    local ok, err = redisClient:connect(ngx.ctx.redisHost, ngx.ctx.redisPort)
    if not ok then
        ngx.log(ngx.ERR, "failed to connect: ", err)
        return false, nil
    end

    local res, err = redisClient:get(redisSessionKey)
    if not res then
        ngx.log(ngx.ERR, "failed to get sessionId (", sessionId, ")", err)
        return false, nil
    end

    if res == ngx.null then
        ngx.log(ngx.ERR, "sessionId (", sessionId, ") not found")
        return false, nil
    end

    local sessionParamTable = jsonHandler.decode(res)
    
    return true, sessionParamTable
end

--- Decrypts a content that came from component and stores in the worker's context
-- (ngx.ctx.sessionParam) the the keys to encrypt/decrypt messages
-- related to this request
-- @param sessionId
-- @param encryptedContent
-- @return <bool, string>
-- bool: indicates if the content has beed decrypted successfully
-- string: the content passed by parameter decrypted if the first return value
-- is true, a nil value otherwise
function _M.decrypt_from_component(sessionId, encryptedContent)
    -- retrieve the session key and iv to decrypt the content
    local ok, sessionParam = retrieve_session_param(sessionId)
    if not ok then
        ngx.log(ngx.ERR, "failed to retrieve session's parameters for ", sessionId)
        return false, nil
    end

    -- store the session parameters on context for future use on reply
    ngx.ctx.sessionParam = sessionParam

    -- decrypt the content
    local key = sessionParam["keyComponentToServer"]
    -- the library requires the data in binary format
    key = key:fromhex()

    -- extract the iv from begin
    local ivLen = string.sub(encryptedContent, 1, 1):byte()
    local iv = string.sub(encryptedContent, 2, ivLen + 1)
    
    -- extract the tag from end
    local tag = string.sub(encryptedContent, -16, -1)
    
    local encContent = string.sub(encryptedContent, ivLen + 2, -17)

    local aes128Gcm = assert(aes:new(key,
                                     nil,
                                     aes.cipher(128, "gcm"),
                                     {iv=iv}))

    local decryptedContent = aes128Gcm:decrypt(encContent, tag)
    if not decryptedContent then
        ngx.log(ngx.ERR, "failed to decrypt content related to session id ", sessionId)
        return false, nil
    end
    
    return true, decryptedContent
end

--- Encrypts a content that came from server. This function uses the key
-- to encrypt previously stored at the worker's context (ngx.ctx.sessionParam),
-- so basically the function decrypt_from_component must be called on request
-- step for this function to make sense and work properly when replying
-- related to this request
-- @param plainContent
-- @return <bool, string>
-- bool: indicates if the content has beed encrypted successfully
-- string: if the first return value is true: the combination of iv_length + 
-- iv + the content passed by parameter encrypted + tag; a nil value otherwise
function _M.encrypt_from_server(plainContent)
    -- retrieve the session key and iv to encrypt the content from the context
    -- stored previously on request
    local sessionParam = ngx.ctx.sessionParam
    if not sessionParam then
        ngx.log(ngx.ERR, "failed to retrieve session's parameters")
        return false, nil
    end

    -- encrypt the content
    local key = sessionParam["keyServerToComponent"]
    local iv = nil

    -- attempt to generate 12 bytes of
    -- cryptographically strong random data for IV
    while iv == nil do
        iv = random.bytes(ivLength, true)
    end

     -- crypto library requires the data in binary format
     key = key:fromhex()

    local aes128Gcm = assert(aes:new(key,
                                     nil,
                                     aes.cipher(128, "gcm"),
                                     {iv=iv}))

    local encryptedContent, tag = aes128Gcm:encrypt(plainContent)
    if not encryptedContent then
        ngx.log(ngx.ERR, "failed to encrypt content related to session id ", sessionId)
        return false, nil
    end

    return true, string.char(#iv) .. iv .. encryptedContent .. tag
end

return _M