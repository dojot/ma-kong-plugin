return {
  fields = {
    kerberos_url = {
      type = "string",
      default = "http://kerberos:8080"
    },
    secure_channel_enabled = {
      type = "boolean",
      default = true
    },
    app_id = {
      type = "array",
      default = {}
    },
    app_key = {
      type = "array", 
      default = {}
    },
    redis_host = {
      type = "string",
      default = "madocker_redis_1"
    },
    redis_port = {
      type = "number",
      default = 6379
    }
  }
}
