local BasePlugin = require "kong.plugins.base_plugin"
local access = require "kong.plugins.mutualauthentication.access"
local body_filter = require "kong.plugins.mutualauthentication.body_filter"
local secureChannel = require "kong.plugins.mutualauthentication.secure_channel"

local AuthPlugin = BasePlugin:extend()

function AuthPlugin:new()
	AuthPlugin.super.new(self, "mutualauthentication")
end

function AuthPlugin:access(conf)
    AuthPlugin.super.access(self)
    
    -- todo: is there a better way to do it? it seems so ugly :/
    if conf.secure_channel_enabled then
        ngx.ctx.redisHost = conf.redis_host
        ngx.ctx.redisPort = conf.redis_port
    end

	access.run(conf)
    ngx.ctx.buffer = ""
    
end

function AuthPlugin:body_filter(conf)
	AuthPlugin.super.body_filter(self)
    body_filter.run(conf)
end

function AuthPlugin:header_filter(conf)
    AuthPlugin.super.header_filter(self)
    -- Removing because content length will change
    ngx.header.content_length = nil
end

return AuthPlugin
