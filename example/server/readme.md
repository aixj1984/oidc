设置环境参数后运行

```
# 使用 Redis 存储
$env:STORAGE_TYPE = "redis"
$env:REDIS_ADDR = "localhost:6379"     # 可选，默认 localhost:6379
$env:REDIS_PASSWORD = ""               # 可选，默认无密码
.\server.exe


```
