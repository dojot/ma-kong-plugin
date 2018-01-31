
package = "mutualauthentication"
version = "0.0-1"
source = {
  url = "https://github.com/dojot/ma-kong-plugin"
}
description = {
  summary = "A Kong plugin that handles the mutual authentication process and the use of secure channel.",
  license = "null"
}
dependencies = {
  "lua ~> 5.1",
  "uuid == 0.2-1"
}
build = {
  type = "builtin",
  modules = {
    ["kong.plugins.mutualauthentication.handler"] = "src/handler.lua",
    ["kong.plugins.mutualauthentication.schema"] = "src/schema.lua",
    ["kong.plugins.mutualauthentication.access"] = "src/access.lua",
    ["kong.plugins.mutualauthentication.body_filter"] = "src/body_filter.lua",
    ["kong.plugins.mutualauthentication.handshake"] = "src/handshake.lua",
    ["kong.plugins.mutualauthentication.secure_channel"] = "src/secure_channel.lua",
    ["kong.plugins.mutualauthentication.util"] = "src/util.lua"
  }
}
