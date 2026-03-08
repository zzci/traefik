# traefik

[English](README.md)

自定义 Traefik Docker 镜像，内置常用插件。

## 快速开始

从 [Releases](https://github.com/zzci/traefik/releases) 下载最新版本，然后：

```bash
tar xzf traefik-vX.X.X.tar.gz
cd traefik

cp env.example .env
# 编辑 .env 配置你的参数

./aa run
```

## 目录结构

```
traefik/
├── aa                    # 辅助脚本
├── docker-compose.yml    # Docker Compose 配置
├── env.example           # 环境变量模板
├── example/
│   ├── middleware.*.yml   # 中间件示例
│   └── service.*.yml     # 服务路由示例
├── services/             # 动态路由配置（自动监听变更）
└── data/
    ├── traefik.yml       # Traefik 静态配置
    ├── ssl/              # ACME 证书存储
    └── logs/             # 访问日志和代理日志
```

## 配置说明

### 环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `ACME_EMAIL` | `admin@example.com` | ACME 证书申请邮箱 |
| `ACME_DISABLE_CNAME` | `true` | 禁用 LEGO 的 CNAME 支持 |
| `ACME_DNS_API` | `https://auth.acme-dns.io` | ACME-DNS API 地址 |
| `TRAEFIK_NETWORK` | `traefik` | Docker 网络名称 |
| `TRAEFIK_SUBNET` | `172.18.0.0/16` | Docker 网络子网 |
| `TRAEFIK_IPV4` | `172.18.0.2` | Traefik 容器 IP |

### 静态配置

编辑 `data/traefik.yml` 修改入口点、证书解析器、插件等。

### 动态路由

将服务配置文件放入 `services/` 目录，从 `example/` 复制并修改即可。

添加一个基本服务，创建 `services/myapp.yml`：

```yml
http:
  routers:
    myapp:
      entryPoints:
        - https
      rule: Host(`myapp.example.com`)
      service: myapp
      middlewares:
        - pwdauth
      tls: true
  services:
    myapp:
      loadBalancer:
        servers:
          - url: http://myapp:8080
```

### 示例文件

**中间件：**

| 文件 | 说明 |
|---|---|
| `middleware.ipauth.yml` | IP 白名单 |
| `middleware.pwdauth.yml` | Basic Auth 认证 |
| `middleware.oidc.yml` | OpenID Connect 认证 |
| `middleware.cors.yml` | CORS 跨域头 |
| `middleware.headers.yml` | 自定义请求/响应头 |
| `middleware.security-headers.yml` | 安全头（HSTS、XSS 等） |
| `middleware.ratelimit.yml` | 请求限流 |
| `middleware.compress.yml` | 响应压缩 |
| `middleware.redirect.yml` | WWW 跳转 |
| `middleware.strip-prefix.yml` | 去除路径前缀 |

**服务：**

| 文件 | 说明 |
|---|---|
| `service.https.yml` | HTTPS 上游（跳过证书验证） |
| `service.httptls.yml` | HTTP challenge 自动证书 |
| `service.dnstls.yml` | DNS challenge 通配符证书（也适用于仪表盘） |
| `service.notls.yml` | 纯 HTTP（无 TLS） |
| `service.tcp.yml` | TCP 透传 |
