设置环境参数后运行

```
$env:CLIENT_ID = "web"
$env:CLIENT_SECRET = "secret"
$env:ISSUER = "http://localhost:9998/"
$env:SCOPES = "openid profile"
$env:PORT = "9999"

app.exe

```

访问 http://localhost:9999/login 登录

访问 http://localhost:9999/logout 登出
