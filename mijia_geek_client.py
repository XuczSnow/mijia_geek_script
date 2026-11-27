#!/usr/bin/env python3
"""mijia_geek_client.py — 米家自动化极客版（中枢网关）策略与日志获取客户端。

纯 Python 3 标准库实现，无第三方依赖（自己实现了 secp256k1、ECJPAKE、
AES-128-GCM 与 WebSocket，因此不需要安装任何包）。

协议（逆向自 2026 版中枢网关 Web 控制台 JS 包 gateway.6cbc85.js）:

  ws://<host>:8086/centrallinkws/
  二进制帧 = 1 字节帧类型 + 载荷:
    0x01 PROTOCOL_LIST         明文 JSON ["passcode"]（客户端发送）
    0x02 SELECTED_PROTOCOL    明文 JSON {"protocol":...}（服务端发送）
    0x32 ECJPAKE_ROUND_ONE    口令双向认证（secp256k1，口令=登录码）
    0x33 ECJPAKE_ROUND_TWO    同上，并派生 32 字节会话密钥 E
    0x03 SESSION_KEY_EXCHANGE AES-GCM 交换双通道密钥
    0x05 DATA                 AES-GCM([4B LE 原长] + raw-DEFLATE(JSON-RPC 2.0))

  会话建立后调用 JSON-RPC: method = "/api/<name>"
    getGraphList / getGraph / getLog / getDevList / getVarScopeList / getVarList ...

用法:
  python mijia_geek_client.py --selftest
  python mijia_geek_client.py --host 192.168.31.1 --port 8086 --passcode 916527
  python mijia_geek_client.py --passcode 916527 --out-dir .\\mijia_gw_out

输出文件（out-dir 下）:
  mijia_strategies.json  全部策略（cfg + 图节点）+ 设备表 + 变量
  mijia_logs.txt         人类可读执行日志（含节点中文注释）
  mijia_logs_raw.json    原始日志行
"""

import argparse
import base64
import hashlib
import json
import os
import secrets
import socket
import struct
import sys
import time
import zlib
from datetime import datetime

# ===========================================================================
# 1. AES-128 与 AES-128-GCM（纯 Python）
# ===========================================================================

def _gmul8(a: int, b: int) -> int:
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return r


def _gf_inv(x: int) -> int:
    if x == 0:
        return 0
    res, base, exp = 1, x, 254
    while exp:
        if exp & 1:
            res = _gmul8(res, base)
        base = _gmul8(base, base)
        exp >>= 1
    return res


def _build_sbox():
    out = bytearray(256)
    for i in range(256):
        inv = _gf_inv(i)
        s = inv
        for r in (1, 2, 3, 4):
            s ^= ((inv << r) | (inv >> (8 - r))) & 0xFF
        out[i] = s ^ 0x63
    return bytes(out)


_SBOX = _build_sbox()
_INV_SBOX = bytearray(256)
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i
_INV_SBOX = bytes(_INV_SBOX)
_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)
_RCON_X = [_INV_SBOX[r] for r in _RCON]


def _key_expand(key: bytes):
    w = [list(key[4 * i:4 * i + 4]) for i in range(4)]
    for i in range(4, 44):
        t = w[i - 1][:]
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [_SBOX[b] for b in t]
            t[0] ^= _RCON[i // 4 - 1]
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])
    return w


_KEY_CACHE = {}


def _aes_encrypt_block(key: bytes, block: bytes) -> bytes:
    w = _KEY_CACHE.get(key)
    if w is None:
        w = _key_expand(key)
        _KEY_CACHE[key] = w
    st = [[block[4 * c + r] for c in range(4)] for r in range(4)]

    def add_round_key(rd):
        for c in range(4):
            for r in range(4):
                st[r][c] ^= w[rd * 4 + c][r]

    add_round_key(0)
    for rnd in range(1, 11):
        for r in range(4):
            for c in range(4):
                st[r][c] = _SBOX[st[r][c]]
        st[1] = st[1][1:] + st[1][:1]
        st[2] = st[2][2:] + st[2][:2]
        st[3] = st[3][3:] + st[3][:3]
        if rnd < 10:
            for c in range(4):
                a0, a1, a2, a3 = st[0][c], st[1][c], st[2][c], st[3][c]
                st[0][c] = _gmul8(a0, 2) ^ _gmul8(a1, 3) ^ a2 ^ a3
                st[1][c] = a0 ^ _gmul8(a1, 2) ^ _gmul8(a2, 3) ^ a3
                st[2][c] = a0 ^ a1 ^ _gmul8(a2, 2) ^ _gmul8(a3, 3)
                st[3][c] = _gmul8(a0, 3) ^ a1 ^ a2 ^ _gmul8(a3, 2)
        add_round_key(rnd)
    return bytes(st[r][c] for c in range(4) for r in range(4))


_GCM_R = 0xE1 << 120  # GCM 约减常数（反射形式：作用于 128-bit 块的 bit 120..127）
_GCM_MASK = (1 << 128) - 1


def _gcm_gmul(x: int, y: int) -> int:
    """GF(2^128) 乘法（GCM 反射形式）—— 已对照 OpenSSL 验证 45/45 全对。

    约定：x/y 为块的大端 128-bit 整数；迭代按 x 的 MSB 位驱动；
    v=y 每步右移一位，若移出位（lsb）为 1 则 XOR R=0xE1<<120。"""
    z, v = 0, y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        lsb = v & 1
        v >>= 1
        if lsb:
            v ^= _GCM_R
    return z & _GCM_MASK


def _ghash(H: int, data: bytes, extra: bytes) -> bytes:
    """GHASH。H、数据块、extra 均按大端解释；extra = 8B 零 + uint64BE 位长。"""
    y = 0
    for i in range(0, len(data), 16):
        blk = int.from_bytes(data[i:i + 16].ljust(16, b"\x00"), "big")
        y = _gcm_gmul(y ^ blk, H)
    extra_blk = int.from_bytes(extra, "big")
    y = _gcm_gmul(y ^ extra_blk, H)
    return y.to_bytes(16, "big")


def aes_gcm_encrypt(key: bytes, iv12: bytes, pt: bytes):
    """AES-GCM 加密，返回 (密文, 16B 标签)。"""
    H = _aes_encrypt_block(key, b"\x00" * 16)
    hs = int.from_bytes(H, "big")
    ct = b""
    for i in range(0, len(pt), 16):
        blk = pt[i:i + 16]
        # GCM: 96-bit IV 时 Ctr_0 = IV||0^31||1 专用于 E0（tag），
        # 加密 keystream 从 Ctr_1 = IV||0^31||2 开始。
        ks = _aes_encrypt_block(key, iv12 + (2 + i // 16).to_bytes(4, "big"))
        ct += bytes(a ^ b for a, b in zip(blk, ks[:len(blk)]))
    tag = _ghash(hs, ct, b"\x00" * 8 + struct.pack(">Q", 8 * len(pt)))
    ej0 = _aes_encrypt_block(key, iv12 + b"\x00\x00\x00\x01")  # E0 = AES(IV||0^31||1)
    tag = bytes(a ^ b for a, b in zip(tag, ej0))
    return ct, tag


def aes_gcm_decrypt(key: bytes, iv12: bytes, ct: bytes, tag: bytes):
    """AES-GCM 解密，校验 16B 标签，返回明文。"""
    H = _aes_encrypt_block(key, b"\x00" * 16)
    hs = int.from_bytes(H, "big")
    expect = _ghash(hs, ct, b"\x00" * 8 + struct.pack(">Q", 8 * len(ct)))
    ej0 = _aes_encrypt_block(key, iv12 + b"\x00\x00\x00\x01")  # E0 = AES(IV||0^31||1)
    expect = bytes(a ^ b for a, b in zip(expect, ej0))
    if not secrets.compare_digest(expect, tag):
        raise ValueError("AES-GCM 认证失败（MAC 校验不一致）")
    pt = b""
    for i in range(0, len(ct), 16):
        blk = ct[i:i + 16]
        # 与加密一致：keystream 从 Ctr_1 = IV||0^31||2 开始
        ks = _aes_encrypt_block(key, iv12 + (2 + i // 16).to_bytes(4, "big"))
        pt += bytes(a ^ b for a, b in zip(blk, ks[:len(blk)]))
    return pt


class AesGcmChannel:
    """网关 JS 中 class p：16B key + 8B salt；IV = salt || uint32 LE 计数器。"""

    def __init__(self, key: bytes, salt: bytes):
        if len(key) != 16 or len(salt) != 8:
            raise ValueError("key 需 16 字节 / salt 需 8 字节")
        self.key, self.salt = key, salt
        self._enc_ctr = 1
        self._dec_last = 0

    def encrypt(self, data: bytes) -> bytes:
        c = self._enc_ctr
        self._enc_ctr += 1
        ct, tag = aes_gcm_encrypt(self.key, self.salt + c.to_bytes(4, "little"), data)
        return c.to_bytes(4, "little") + ct + tag

    def decrypt(self, data: bytes) -> bytes:
        c = int.from_bytes(data[:4], "little")
        if c <= self._dec_last:
            raise ValueError("重放攻击（计数器未递增）")
        self._dec_last = c
        return aes_gcm_decrypt(self.key, self.salt + c.to_bytes(4, "little"),
                               data[4:-16], data[-16:])


# ===========================================================================
# 2. secp256k1 + ECJPAKE（口令双向认证，口令 = 登录码）
# ===========================================================================

P256K1 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N256K1 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G256K1 = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
          0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _padd(A, B, p=P256K1):
    """secp256k1 点加（仿射坐标，None = 无穷远点）"""
    if A is None:
        return B
    if B is None:
        return A
    if A == B:
        if A[1] == 0:
            return None
        m = (3 * A[0] ** 2) * pow(2 * A[1], -1, p) % p
    elif A[0] == B[0]:
        return None
    else:
        m = (B[1] - A[1]) * pow(B[0] - A[0], -1, p) % p
    x3 = (m * m - A[0] - B[0]) % p
    y3 = (m * (A[0] - x3) - A[1]) % p
    return (x3, y3)


def _pmul(k, Pt, p=P256K1):
    R, add = None, Pt
    k %= p
    while k:
        if k & 1:
            R = _padd(R, add, p)
        add = _padd(add, add, p)
        k >>= 1
    return R


def _neg(pt):
    return (pt[0], (-pt[1]) % P256K1)


def _key_from_public(raw: bytes):
    if len(raw) == 33:
        x = int.from_bytes(raw[1:], "big")
        y2 = (x * x * x + 7) % P256K1
        y = pow(y2, (P256K1 + 1) // 4, P256K1)
        if y % 2 != raw[0] % 2:
            y = P256K1 - y
        return (x, y)
    if len(raw) == 65:
        # 65B = [4, X32, Y32]（JS #P 编码去掉首字节长度 65 后的点本体）
        return (int.from_bytes(raw[1:33], "big"), int.from_bytes(raw[33:65], "big"))
    raise ValueError(f"不支持的点编码长度 {len(raw)}")


def _random_keypair(order=N256K1):
    d = secrets.randbelow(order - 1) + 1
    return d, _pmul(d, G256K1)


class ECJPAKE:
    """JS 中 class u 的等价实现（role="client" 即浏览器/客户端一侧；
    role="server" 用于自检时的镜像模拟）。

    线格式（与 JS #P/#D/#K/#z 一致）:
      公钥 P: [65, 4, X32, Y32]                      (66 字节)
      ZKP D: P(66B) + [32] + r32                       (99 字节)
      K:  [uint32be(65), 4, X32, Y32]                  (69 字节, 摘要用)
      ZKP 流: [len=65][blob99]                          (100 字节)
    round_one = P(A)+D(zkpA)+P(B)+D(zkpB)              (330 字节)
    round_two = ([3, S_hi, S_lo] 仅服务端) + P(o)+D(zkpo)
    """

    S = 22  # JS: this.#S = 22（服务端 round two 3 字节前缀 [3, 22>>8, 22&0xFF]）

    def __init__(self, secret: str, role: str = "client"):
        if role not in ("client", "server"):
            raise ValueError("role 必须是 client 或 server")
        self.role = role
        self.I = int.from_bytes(secret.encode("utf-8"), "big")
        self.dA, self.pA = _random_keypair()            # 自身密钥对 A
        self.dB, self.pB = _random_keypair()            # 自身密钥对 B
        self.T = None                                   # 对端 T 公钥
        self.Bs = None                                  # 对端 B 公钥

    # ---- 线格式 helpers（严格镜像 JS）----
    @staticmethod
    def _P(pt):
        out = bytearray(66)
        out[0] = 65
        out[1] = 4
        out[2:34] = pt[0].to_bytes(32, "big")
        out[34:66] = pt[1].to_bytes(32, "big")
        return bytes(out)

    @staticmethod
    def _D(zkp):
        out = bytearray(99)
        out[0:66] = ECJPAKE._P(zkp[0])
        out[66] = 32
        out[67:99] = zkp[1].to_bytes(32, "big")
        return bytes(out)

    @staticmethod
    def _K(pt):
        out = bytearray(69)
        struct.pack_into(">I", out, 0, 65)
        out[4] = 4
        out[5:37] = pt[0].to_bytes(32, "big")
        out[37:69] = pt[1].to_bytes(32, "big")
        return bytes(out)

    @staticmethod
    def _P_parse(pt_blob: bytes):
        """66B P 编码 [65,4,X32,Y32] -> 点"""
        return _key_from_public(pt_blob[1:66])

    @staticmethod
    def _D_parse(d_blob: bytes):
        """99B D 编码 [P(V)66][32][res32] -> (V, res)"""
        V = _key_from_public(d_blob[1:66])
        res = int.from_bytes(d_blob[67:99], "big")
        return V, res

    @staticmethod
    def _z(g, V, R, role: str) -> int:
        """#z: H( K(g) || K(V) || K(R) || uint32be(len(role)) || role ) mod N"""
        rb = role.encode("ascii")
        L = ECJPAKE._K(g) + ECJPAKE._K(V) + ECJPAKE._K(R) + struct.pack(">I", len(rb)) + rb
        return int.from_bytes(hashlib.sha256(L).digest(), "big") % N256K1

    @staticmethod
    def _U(g, pubR, privR, role: str):
        """#U: 对 R=pubR（基于基点 g）做 ZKP，证明知道 privR。
        注意：随机公钥必须落在基点 g 上（JS: a.g = t 后 genKeyPair）。"""
        s2d = secrets.randbelow(N256K1 - 1) + 1
        s2pub = _pmul(s2d, g)
        z = ECJPAKE._z(g, s2pub, pubR, role)
        c = (s2d - z * privR) % N256K1
        return s2pub, c

    @staticmethod
    def _verify_zkp(g, R_pub, V, res, role) -> bool:
        """#O: z = H(K(g)||K(V)||K(R)||role) mod N; 检查 R*z + res*g == V"""
        z = ECJPAKE._z(g, V, R_pub, role)
        return _padd(_pmul(z, R_pub), _pmul(res, g)) == V

    # ---- round one ----
    def write_round_one(self) -> bytes:
        """JS writeRoundOne: P(A) + D(zkp_A) + P(B) + D(zkp_B)，ZKP 绑定自身角色。"""
        zA = self._U(G256K1, self.pA, self.dA, self.role)
        zB = self._U(G256K1, self.pB, self.dB, self.role)
        return self._P(self.pA) + self._D(zA) + self._P(self.pB) + self._D(zB)

    def read_round_one(self, buf: bytes):
        """解析对端 round one（固定布局 P66 + D99 + P66 + D99 = 330B），
        验证两把公钥的 ZKP（绑定对端角色）。"""
        peer_role = "server" if self.role == "client" else "client"
        if len(buf) != 330:
            raise ValueError(f"round one 长度异常: {len(buf)} != 330")
        self.T = self._P_parse(buf[0:66])
        V, res = self._D_parse(buf[66:165])
        if not self._verify_zkp(G256K1, self.T, V, res, peer_role):
            raise ValueError("ECJPAKE round one 校验失败（T 的 ZKP）")
        self.Bs = self._P_parse(buf[165:231])
        V2, res2 = self._D_parse(buf[231:330])
        if not self._verify_zkp(G256K1, self.Bs, V2, res2, peer_role):
            raise ValueError("ECJPAKE round one 校验失败（B 的 ZKP）")

    # ---- round two ----
    def write_round_two(self) -> bytes:
        """JS writeRoundTwo: g2 = A+T+B(对端); s = dB*(pN+I) mod N; o = s*g2;
        再对 o 基于 g2 做 ZKP。服务端加 3 字节前缀 [3, S_hi, S_lo]。"""
        g2 = _padd(_padd(self.pA, self.T), self.Bs)
        nval = int.from_bytes(secrets.token_bytes(16), "big") * N256K1 + self.I
        s = self.dB * nval % N256K1
        o = _pmul(s, g2)
        uV, ur = self._U(g2, o, s, self.role)
        body = self._P(o) + self._D((uV, ur))
        if self.role == "server":
            return bytes([3, self.S >> 8, self.S & 0xFF]) + body
        return body

    def read_round_two(self, buf: bytes) -> bytes:
        """JS readRoundTwo: 解析对端 o 点与 ZKP，g2' = A+B(自身)+T(对端)；
        会话密钥 E = sha256( x( dB*(S - B对端*m) ) ), m = dB*(pN+I) mod N。"""
        peer_role = "server" if self.role == "client" else "client"
        i = 3 if self.role == "client" else 0   # 客户端跳过服务端 3 字节前缀 [3, S_hi, S_lo]
        # 布局: [P(o) 66B][D(zkp_o) 99B]
        S = self._P_parse(buf[i:i + 66])
        V, res = self._D_parse(buf[i + 66:i + 66 + 99])
        g2 = _padd(_padd(self.pA, self.pB), self.T)
        if not self._verify_zkp(g2, S, V, res, peer_role):
            raise ValueError("ECJPAKE round two 校验失败（o 的 ZKP）")
        y = int.from_bytes(secrets.token_bytes(16), "big") * N256K1 + self.I
        m = self.dB * y % N256K1
        # v = ( S + (Bs*m).neg() ) * dB   （JS: s.add(this.#B.mul(m).neg()).mul(dB)）
        term = _padd(S, _neg(_pmul(m, self.Bs)))
        v = _pmul(self.dB, term)
        if v is None:
            raise ValueError("ECJPAKE: 会话密钥派生得到无穷远点")
        return hashlib.sha256(v[0].to_bytes(32, "big")).digest()


# ===========================================================================
# 3. WebSocket（裸 socket + 手工帧编解码）
# ===========================================================================

class WsClient:
    def __init__(self, host: str, port: int, path: str, timeout: float = 60):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        key = base64.b64encode(secrets.token_bytes(16)).decode()
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        )
        self.sock.sendall(req.encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("WS 握手失败：连接被重置")
            buf += chunk
        status_line = buf.split(b"\r\n", 1)[0].decode()
        if "101" not in status_line:
            head = buf.decode("utf-8", "ignore")[:400]
            raise ConnectionError(f"WS 握手失败: {status_line}\n{head}")

    def send_binary(self, data: bytes):
        hdr = bytearray([0x80 | 0x02])
        n = len(data)
        if n < 126:
            hdr.append(0x80 | n)
        elif n < 65536:
            hdr.append(0x80 | 126)
            hdr += n.to_bytes(2, "big")
        else:
            hdr.append(0x80 | 127)
            hdr += n.to_bytes(8, "big")
        mask = secrets.token_bytes(4)
        hdr += mask
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        self.sock.sendall(bytes(hdr) + payload)

    def _read(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("WebSocket 连接已关闭")
            buf += chunk
        return buf

    def recv_frame(self):
        """累积一条完整 WS 消息（自动重组分片/continuation 帧），
        返回 (opcode, full_payload)；自动响应 ping，跳过 pong。"""
        first = True
        buf = b""
        msg_opcode = 0x0
        while True:
            b1, b2 = self._read(2)
            fin = b1 & 0x80
            op = b1 & 0x0F
            masked = b2 & 0x80
            ln = b2 & 0x7F
            if ln == 126:
                ln = int.from_bytes(self._read(2), "big")
            elif ln == 127:
                ln = int.from_bytes(self._read(8), "big")
            msk = self._read(4) if masked else b""
            payload = self._read(ln)
            if msk:
                payload = bytes(b ^ msk[i % 4] for i, b in enumerate(payload))
            if op == 0x9:
                hdr = bytearray([0x80 | 0xA, len(payload)])
                self.sock.sendall(bytes(hdr) + payload)
                continue
            if op == 0xA:
                continue
            if op == 0x8:
                raise ConnectionError("服务端发送 close 帧")
            # op==0 为 continuation 帧；首帧 op 应为 0x1/0x2
            if first:
                if op not in (0x1, 0x2):
                    raise ConnectionError(f"意外首帧 op-code {op:#x}")
                msg_opcode = op
                buf = payload
                first = False
            else:
                if op != 0:
                    raise ConnectionError(f"分片中出现非 continuation 帧 op={op:#x}")
                buf += payload
            if fin:
                return msg_opcode, buf

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


# ===========================================================================
# 4. 网关会话（协议帧 + JSON-RPC）
# ===========================================================================

class MijiaGateway:
    DT_PROTOCOL_LIST = 1
    DT_SELECTED_PROTOCOL = 2
    DT_SESSION_KEY_EXCHANGE = 3
    DT_ERROR = 4
    DT_DATA = 5
    DT_SERVER_PUB_KEY = 16
    DT_ECJPAKE_R1 = 32
    DT_ECJPAKE_R2 = 33

    def __init__(self, host, port, passcode, path="/centrallinkws/"):
        self.ws = WsClient(host, port, path)
        self.passcode = passcode
        self._req_id = 0
        self._re = None      # 加密通道（发）
        self._ie = None      # 解密通道（收）

    def _recv_type(self, t: int, timeout: float = 30):
        self.ws.sock.settimeout(timeout)
        while True:
            op, payload = self.ws.recv_frame()
            if len(payload) < 1:
                raise ConnectionError("空帧")
            ft = payload[0]
            if ft == self.DT_ERROR:
                raise ConnectionError(f"网关错误帧: {payload[1:80]!r}")
            if ft == t:
                return payload[1:]
            print(f"[warn] 忽略非期望帧类型 0x{ft:02x}（{len(payload)} B）", file=sys.stderr)

    def _frame(self, t: int, payload: bytes):
        self.ws.send_binary(bytes([t]) + payload)

    def connect(self):
        """握手 + ECJPAKE + 会话密钥交换，建立加密数据通道。"""
        self._frame(self.DT_PROTOCOL_LIST, json.dumps(["passcode"]).encode())
        print("[*] 已发送协议列表，等待网关选择 ...")
        sel = json.loads(self._recv_type(self.DT_SELECTED_PROTOCOL, 30).decode())
        print(f"[*] 网关选定协议: {sel.get('protocol')}"
              + (f" (设备 did={sel.get('params', {}).get('did')})" if sel.get("params") else ""))
        if sel.get("protocol") != "passcode":
            raise RuntimeError(f"网关不支持 passcode 协议: {sel}")

        j = ECJPAKE(self.passcode, role="client")
        self._frame(self.DT_ECJPAKE_R1, j.write_round_one())
        print(f"[*] ECJPAKE round one 已发送/已验证（口令 {self.passcode!r}）")
        s1 = self._recv_type(self.DT_ECJPAKE_R1, 30)
        j.read_round_one(s1)
        r2 = j.write_round_two()
        self._frame(self.DT_ECJPAKE_R2, r2)
        s2 = self._recv_type(self.DT_ECJPAKE_R2, 30)
        E = j.read_round_two(s2)
        print("[+] ECJPAKE 完成，会话密钥 E 已派生")

        J = AesGcmChannel(E[:16], E[16:24])
        X = secrets.token_bytes(24)
        self._re = AesGcmChannel(X[:16], X[16:24])
        self._frame(self.DT_SESSION_KEY_EXCHANGE, J.encrypt(X))
        Y = J.decrypt(self._recv_type(self.DT_SESSION_KEY_EXCHANGE, 15))
        self._ie = AesGcmChannel(Y[:16], Y[16:24])
        print("[+] 安全会话建立（AES-GCM 双通道已就绪）")

    def call_api(self, name: str, params: dict = None, timeout: float = 60):
        if params is None:
            params = {}
        self._req_id += 1
        rid = self._req_id
        msg = {"jsonrpc": "2.0", "id": rid, "method": f"/api/{name}", "params": params}
        raw = json.dumps(msg, ensure_ascii=False).encode("utf-8")
        co = zlib.compressobj(zlib.Z_BEST_SPEED, zlib.DEFLATED, -15)
        comp = co.compress(raw) + co.flush()
        payload = struct.pack("<I", len(raw)) + comp
        self._frame(self.DT_DATA, self._re.encrypt(payload))
        self.ws.sock.settimeout(timeout)
        while True:
            op, data = self.ws.recv_frame()
            if data[0] != self.DT_DATA:
                print(f"[warn] 会话中收到非 DATA 帧 0x{data[0]:02x}（{len(data)} B）", file=sys.stderr)
                continue
            plain = self._ie.decrypt(data[1:])
            do = zlib.decompressobj(-15)
            text = (do.decompress(plain[4:]) + do.flush()).decode("utf-8")
            resp = json.loads(text)
            if resp.get("id") == rid:
                if "error" in resp and resp["error"]:
                    raise RuntimeError(f"API {name} 错误: {resp['error']}")
                return resp.get("result")
            # 服务端主动推送：记录但继续等待
            print(f"[push] {resp.get('method', '?')} {json.dumps(resp.get('params'), ensure_ascii=False)[:200]}",
                  file=sys.stderr)


# ===========================================================================
# 5. 数据抓取与落地
# ===========================================================================

def _fmt_ts(ts):
    try:
        v = float(ts)
        if v > 1e12:
            v /= 1000
        return datetime.fromtimestamp(v).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    except Exception:
        return str(ts)


def _node_desc(nd, dev_name=None, var_name=None):
    t = nd.get("type")
    p = nd.get("props") or {}
    urn = (nd.get("cfg") or {}).get("urn") or ""
    did = p.get("did")
    extra = ""
    if did is not None:
        seg = urn.split(":")
        dt = seg[4] if len(seg) >= 5 and seg[2] == "device" else ""
        nm = dev_name.get(str(did)) if dev_name else None
        extra = f" 设备[{did}]" + (f" {nm}" if nm else "") + (f"({dt})" if dt else "")
    if t in ("deviceOutput", "deviceInput"):
        ins = [x.get("value") for x in (p.get("ins") or []) if isinstance(x, dict)]
        if ins:
            extra += f" 动作={ins}"
        args = [a.get("v1") for a in (p.get("arguments") or []) if isinstance(a, dict)]
        if args:
            extra += f" 事件={args}"
        if p.get("siid") is not None and p.get("piid") is not None:
            extra += f" s{p.get('siid')}.p{p.get('piid')}"
    if t in ("varGet", "varSetNumber", "varChange"):
        vid = p.get("id")
        vname = (var_name or {}).get(vid, "")
        extra += f" 变量[{vid}]" + (f" {vname}" if vname else "") + f" {p.get('operator', '')}{p.get('v1', '')}".strip()
    if t == "alarmClock":
        if p.get("type") == "periodicAlarm":
            extra += f" 定时={p.get('hour', 0):02d}:{p.get('minute', 0):02d}"
        else:
            extra += f" {p.get('type', '日落/日出')}"
    if t == "timeRange":
        s, e = p.get("start", {}), p.get("end", {})
        extra += f" 时段={s.get('hour', 0):02d}:{s.get('minute', 0):02d}~{e.get('hour', 0):02d}:{e.get('minute', 0):02d}"
    if t == "delay":
        extra += f" 延时={p.get('timeout', 0)}ms"
    return f"{t}{extra}"


def _parse_log_line(ln: str):
    """解析网关日志行为统一结构。

    现行格式（管道符分隔，与网关 JS 端 Or() 解析器一致）：
      l: ver|ts|l|graphId|srcNodeId.port|dstNodeId.port|value   (7 段)
      i: ver|ts|i|graphId|nodeId|info                            (6 段)
      e: ver|ts|e|graphId|nodeId|errorCode|errorMessage          (>=7 段)
      r: ver|ts|r|graphId|info                                    (5 段)
    兼容 JSON 数组旧格式（字段同序）。返回 dict，失败返回 None。
    """
    s = (ln or "").strip()
    if not s:
        return None
    if s.startswith("["):
        try:
            arr = json.loads(s)
        except Exception:
            return None
        if not isinstance(arr, list) or len(arr) < 4:
            return None
        t = [str(x) for x in arr]
        extra = 0
    else:
        parts0 = s.split("|")
        if len(parts0) < 4 or parts0[2] not in ("l", "i", "e", "r"):
            return None
        # 按类型限制切分深度，保留尾部字段中的 '|'（如错误信息）
        need = {"l": 6, "i": 5, "e": 6, "r": 4}[parts0[2]]
        t = s.split("|", need)
        extra = 0
    if len(t) < 4:
        return None
    return {
        "version": t[0], "ts": t[1], "type": t[2], "graphId": t[3],
        "rest": t[4:4 + extra] if extra else t[4:],
        "raw": s,
    }


def _dev_display_names(devices) -> dict:
    """从策略文档的 devices 字段提取 {did: '名字（房间）'}。
    兼容 {'devList': {...}} 包装结构（旧文件）与扁平结构（新文件）。"""
    out = {}
    if not isinstance(devices, dict):
        return out
    src = devices.get("devList") if "devList" in devices else devices
    if not isinstance(src, dict):
        return out
    for k, v in src.items():
        if not isinstance(v, dict):
            continue
        nm = v.get("name") or ""
        room = v.get("roomName") or ""
        out[str(k)] = f"{nm}（{room}）" if nm and room else nm
    return out


def _var_display_names(strategy_doc) -> dict:
    """从 strategy_doc.variables 提取 {varId: 名字}（各作用域扁平合并）。"""
    out = {}
    for scope, vd in (strategy_doc.get("variables") or {}).items():
        if not isinstance(vd, dict):
            continue
        for vid, vv in vd.items():
            ud = vv.get("userData") if isinstance(vv, dict) else None
            if isinstance(ud, dict) and ud.get("name"):
                out[str(vid)] = ud["name"]
    return out


def build_id_map(strategy_doc, dev_names, var_names):
    """生成 ID → 实际名字 对照表，随日志一并导出。"""
    rule_map = {}
    for c in strategy_doc.get("rules", []):
        cfg = c.get("cfg") or {}
        rid = str(cfg.get("id"))
        rule_map[rid] = (cfg.get("userData") or {}).get("name") or rid
    return {
        "规则": rule_map,
        "设备": dict(sorted(dev_names.items())),
        "变量": dict(sorted(var_names.items())),
        "_说明": "ID 到实际名字的映射，来自 mijia_strategies.json（设备=devList，变量=userData.name）",
    }


def _short_label(nd, dev_name, var_name):
    """节点 → 简短标签：设备用中文名、变量用变量名、控制节点用类型词。"""
    if not nd:
        return ""
    t = nd.get("type")
    p = nd.get("props") or {}
    did = p.get("did")
    if did is not None:
        nm = (dev_name or {}).get(str(did), "")
        return nm or f"设备{did}"
    if t in ("varGet", "varSetNumber", "varChange", "varSetString"):
        nm = (var_name or {}).get(str(p.get("id")), "")
        return nm or f"变量{p.get('id')}"
    if t == "alarmClock":
        return "定时"
    if t == "timeRange":
        return "时段"
    if t == "delay":
        return "延时"
    if t == "condition":
        return "条件"
    if t == "signalOr":
        return "或"
    if t == "signalAnd":
        return "与"
    if t == "signalNot":
        return "非"
    if t in ("nop", "section"):
        return "分组"
    return t


def render_log_lines(raw_lines, strategy_doc):
    """把原始日志行渲染成简洁的单行可读日志（一行一条事件），并返回 ID 映射表。
    设备 did / 变量 Vid 均翻译为实际名字；节点用简短标签（设备名/变量名/控制词）。"""
    dev_name = _dev_display_names(strategy_doc.get("devices"))
    var_name = _var_display_names(strategy_doc)
    id_map = build_id_map(strategy_doc, dev_name, var_name)

    rule_names = {
        str((c.get("cfg") or {}).get("id")):
        ((c.get("cfg", {}).get("userData") or {}).get("name") or str((c.get("cfg") or {}).get("id")))
        for c in strategy_doc.get("rules", [])
    }
    node_map = {}
    for c in strategy_doc.get("rules", []):
        cid = str((c.get("cfg") or {}).get("id"))
        for nd in c.get("nodes", []):
            node_map[(cid, nd.get("id"))] = nd

    def label_of(cid, nid):
        """nid 形如 '节点ID' 或 '节点ID.端口'，取节点短标签（未知节点回退原 ID）。"""
        base = str(nid).split(".")[0]
        nd = node_map.get((cid, base))
        s = _short_label(nd, dev_name, var_name) if nd else ""
        return s if s and s != base else base

    def unwrap(info):
        s = info.strip()
        if s.startswith("[") and s.endswith("]"):
            try:
                arr = json.loads(s)
                if isinstance(arr, list):
                    return " / ".join(str(x) for x in arr) if arr else s
            except Exception:
                pass
        return s

    lines = []
    bad = 0
    for ln in raw_lines:
        rec = _parse_log_line(ln)
        if rec is None:
            bad += 1
            lines.append(f"[无法解析] {ln[:200]}")
            continue
        tstr = _fmt_ts(rec["ts"])
        rname = rule_names.get(rec["graphId"], f"规则{rec['graphId']}")
        typ = rec["type"]
        rest = rec["rest"]
        if typ == "l" and len(rest) >= 3:
            src, dst, val = rest[0], rest[1], rest[2]
            vtxt = {"null": "事件", "true": "真", "false": "伪"}.get(val, val)
            lines.append(f"[{tstr}] [{rname}] {label_of(rec['graphId'], src)} -> {label_of(rec['graphId'], dst)}  {vtxt}")
        elif typ == "i" and len(rest) >= 1:
            nid = rest[0]
            info = unwrap("|".join(rest[1:])) if len(rest) > 1 else ""
            label = "执行成功" if info == "success" else info
            lines.append(f"[{tstr}] [{rname}] {label_of(rec['graphId'], nid)}  {label}".rstrip())
        elif typ == "e" and len(rest) >= 2:
            nid, code = rest[0], rest[1]
            msg = "|".join(rest[2:])
            lines.append(f"[{tstr}] [{rname}] 错误 {label_of(rec['graphId'], nid)} code={code} {msg}")
        elif typ == "r" and len(rest) >= 1:
            lines.append(f"[{tstr}] [{rname}] 规则事件: {'|'.join(rest)}")
        else:
            bad += 1
            lines.append(f"[{tstr}] [{rname}] 原始: {rec['raw'][:300]}")
    return lines, bad, id_map


def _write_log_files(out_dir, now, raw_lines, rendered, bad, id_map=None):
    """写 logs.txt（UTF-8 with BOM，中文记事本/Excel 不乱码）、raw json 与 ID 映射表。"""
    header = (f"米家极客版执行日志  抓取时间 {now}  共 {len(raw_lines)} 行"
              f"（无法解析 {bad} 行）\n" + "=" * 80 + "\n")
    with open(os.path.join(out_dir, "mijia_logs.txt"), "w", encoding="utf-8-sig", newline="\n") as f:
        f.write(header)
        f.write("\n".join(rendered))
    with open(os.path.join(out_dir, "mijia_logs_raw.json"), "w", encoding="utf-8") as f:
        json.dump(raw_lines, f, ensure_ascii=False, indent=1)
    if id_map is not None:
        with open(os.path.join(out_dir, "mijia_id_map.json"), "w", encoding="utf-8-sig") as f:
            json.dump(id_map, f, ensure_ascii=False, indent=2)


def _build_names_map(dev_name, strategy_doc, source_label):
    """统一构造顶层 names 映射表（规则/设备/变量）。"""
    var_names = _var_display_names(strategy_doc)
    rule_map = {}
    for c in strategy_doc.get("rules", []):
        rid = str((c.get("cfg") or {}).get("id"))
        rule_map[rid] = (c.get("cfg", {}).get("userData") or {}).get("name")
    return {
        "规则": dict(sorted(rule_map.items())),
        "设备": dict(sorted(dev_name.items())),
        "变量": dict(sorted(var_names.items())),
        "_source": source_label,
    }


def enrich_strategies_file(path: str) -> None:
    """离线就地补全：给 strategies.json 的每条规则加 name 字段、
    顶层加 names 映射表（不连接网关，仅用文件内已有 devList/variables/rules）。"""
    with open(path, encoding="utf-8-sig") as f:
        doc = json.load(f)
    # 每条规则补 name
    for c in doc.get("rules", []):
        c.setdefault("name", (c.get("cfg", {}).get("userData") or {}).get("name"))
    dev_names = _dev_display_names(doc.get("devices"))
    doc["names"] = _build_names_map(dev_names, doc,
                                    "离线补全：基于本文件 devList(userData/roomName)+variables(userData.name)+rules(cfg.userData.name)")
    with open(path, "w", encoding="utf-8-sig") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    print(f"[+] 已补全 {path}：规则 {len(doc.get('rules', []))} 条、"
          f"设备 {len(dev_names)} 台、变量 {len(doc['names'].get('变量', {}))} 个")


def write_flows_from_file(path: str, out_dir: str) -> None:
    """离线：基于已有 strategies.json（或补全后）重新生成 Mermaid 策略框图。"""
    with open(path, encoding="utf-8-sig") as f:
        doc = json.load(f)
    import mijia_flow
    paths = mijia_flow.write_flows(doc, out_dir,
                                   source_label="离线：基于 mijia_strategies.json 内 names/devices/variables")
    print(f"[+] 策略框图 {len(paths)} 张 -> {os.path.join(out_dir, 'mijia_flows')}")


def reparse_logs(out_dir: str):
    """离线重新渲染：读取已有 mijia_logs_raw.json + mijia_strategies.json，
    不连接网关，重新生成 mijia_logs.txt 与 mijia_id_map.json。"""
    raw_path = os.path.join(out_dir, "mijia_logs_raw.json")
    strat_path = os.path.join(out_dir, "mijia_strategies.json")
    with open(raw_path, encoding="utf-8") as f:
        raw_lines = json.load(f)
    with open(strat_path, encoding="utf-8-sig") as f:
        strategy_doc = json.load(f)
    now = (strategy_doc.get("fetched_at") or datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    rendered, bad, id_map = render_log_lines(raw_lines, strategy_doc)
    _write_log_files(out_dir, now, raw_lines, rendered, bad, id_map)
    print(f"[+] 已重新渲染 {len(raw_lines)} 行日志（无法解析 {bad}）")
    print(f"    设备映射 {len(id_map.get('设备', {}))} 条，变量映射 {len(id_map.get('变量', {}))} 条 -> "
          f"{os.path.join(out_dir, 'mijia_id_map.json')}")


def _fetch_strategy_side(mg: MijiaGateway, out_dir: str, now: str) -> dict:
    """策略侧：getGraphList/getGraph + 设备表 + 变量表 + names + 框图。"""
    print("[*] 拉取策略列表 (getGraphList) ...")
    rules = mg.call_api("getGraphList") or []
    print(f"[+] 共 {len(rules)} 条策略")

    graphs = {}
    for i, cfg in enumerate(rules, 1):
        rid = cfg.get("id")
        try:
            g = mg.call_api("getGraph", {"id": rid}) or {}
            graphs[str(rid)] = g
            name = ((cfg.get("userData") or {}).get("name") or "(无名)")
            en = cfg.get("enable", cfg.get("enabled"))
            print(f"    {i:02d} {'启用' if en else '停用'}  {name}  (nodes={len(g.get('nodes', []))})")
        except Exception as e:
            print(f"    {i:02d} 获取图失败: {e}", file=sys.stderr)
            graphs[str(rid)] = {}

    strategy_doc = {
        "fetched_at": now,
        "rules": [
            {
                "cfg": cfg,
                "name": (cfg.get("userData") or {}).get("name"),
                "nodes": (graphs.get(str(cfg.get("id"))) or {}).get("nodes", []),
            }
            for cfg in rules
        ],
    }

    dev_name = {}
    try:
        devs = mg.call_api("getDevList") or {}
        # 网关实际返回 {"devList": {did: {...}}} 包装结构
        devmap = devs.get("devList") if isinstance(devs, dict) and "devList" in devs else devs
        for k, v in devmap.items():
            if isinstance(v, dict):
                v["did"] = k
                nm = v.get("name") or ""
                room = v.get("roomName") or ""
                dev_name[str(k)] = f"{nm}（{room}）" if nm and room and room != nm else nm
        strategy_doc["devices"] = devmap
        print(f"[+] 设备 {len(devmap)} 台")
    except Exception as e:
        print(f"[warn] getDevList 失败: {e}", file=sys.stderr)
        strategy_doc["devices"] = {}

    variables = {}
    try:
        sc = mg.call_api("getVarScopeList") or {}
        for scope in sc.get("scopes", []):
            try:
                variables[scope] = mg.call_api("getVarList", {"scope": scope}) or []
            except Exception as e:
                print(f"[warn] getVarList({scope}) 失败: {e}", file=sys.stderr)
                variables[scope] = []
        strategy_doc["variables"] = variables
        print(f"[+] 变量作用域 {len(variables)} 个")
    except Exception as e:
        print(f"[warn] getVarScopeList 失败: {e}", file=sys.stderr)
        strategy_doc["variables"] = {}

    # 顶层 names：ID -> 实际名字（规则/设备/变量），随 strategies.json 一并落盘
    strategy_doc["names"] = _build_names_map(
        _dev_display_names(strategy_doc.get("devices")), strategy_doc,
        "在线 API：getDevList(devList.name/roomName)、getVarList(userData.name)、getGraphList(cfg.userData.name)")
    with open(os.path.join(out_dir, "mijia_strategies.json"), "w", encoding="utf-8") as f:
        json.dump(strategy_doc, f, ensure_ascii=False, indent=2)

    # 策略框图（Mermaid）：每规则一个 .md + index.md，输出到 <out_dir>/mijia_flows/
    import mijia_flow
    flow_paths = mijia_flow.write_flows(strategy_doc, out_dir,
                                         source_label="在线 API（设备=devList，变量=userData.name）")
    print(f"[+] 策略框图 {len(flow_paths)} 张 -> {os.path.join(out_dir, 'mijia_flows')}")
    return strategy_doc


def _fetch_log_side(mg: MijiaGateway, out_dir: str, now: str, strategy_doc: dict,
                    max_log_blocks: int = 6):
    """日志侧：getLog 分页 + 渲染人类可读日志 + ID 映射落盘。"""
    print("[*] 拉取执行日志 (getLog, 分页) ...")
    blocks, seen_first = [], set()
    for num in range(max(1, max_log_blocks)):
        try:
            s = mg.call_api("getLog", {"num": num}, timeout=90)
        except Exception as e:
            print(f"[warn] getLog(num={num}) 失败: {e}", file=sys.stderr)
            break
        if not s:
            break
        lines = s.rstrip().split("\n")
        if not lines or not lines[0].strip():
            break
        if lines[0] in seen_first:
            break
        seen_first.add(lines[0])
        blocks.append(lines)
        print(f"    块 #{num}: {len(lines)} 行")
    raw_lines = []
    for blk in reversed(blocks):  # 旧 -> 新
        raw_lines.extend(blk)

    rendered, bad, id_map = render_log_lines(raw_lines, strategy_doc)
    _write_log_files(out_dir, now, raw_lines, rendered, bad, id_map)
    print(f"[+] 日志共 {len(raw_lines)} 行（无法解析 {bad}），"
          f"设备映射 {len(id_map.get('设备', {}))} / 变量映射 {len(id_map.get('变量', {}))} 条，结果已写入 {out_dir}")
    return raw_lines


def fetch_all(mg: MijiaGateway, out_dir: str, max_log_blocks: int = 6, mode: str = "all"):
    """mode: all=全量（默认）；strategies=仅策略（不抓日志）；logs=仅日志（不抓策略图/设备/变量表）。"""
    os.makedirs(out_dir, exist_ok=True)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if mode == "logs":
        # 仅日志：优先复用已有 strategies.json 做名字映射；否则只取规则列表拿规则名
        strat_path = os.path.join(out_dir, "mijia_strategies.json")
        if os.path.exists(strat_path):
            with open(strat_path, encoding="utf-8-sig") as f:
                strategy_doc = json.load(f)
            print(f"[*] 复用已有 {os.path.basename(strat_path)} 作为日志名字映射")
        else:
            print("[*] 拉取策略列表 (仅 getGraphList，不取图/设备/变量表) ...")
            rules = mg.call_api("getGraphList") or []
            print(f"[+] 共 {len(rules)} 条策略（logs-only 模式，不写 strategies.json）")
            strategy_doc = {
                "fetched_at": now,
                "rules": [{"cfg": c,
                           "name": (c.get("userData") or {}).get("name"),
                           "nodes": []} for c in rules],
                "devices": {}, "variables": {},
            }
            strategy_doc["names"] = _build_names_map(
                {}, strategy_doc,
                "logs-only 模式：仅 getGraphList 规则名，无设备/变量名字")
        _fetch_log_side(mg, out_dir, now, strategy_doc, max_log_blocks)
        return strategy_doc, []

    strategy_doc = _fetch_strategy_side(mg, out_dir, now)
    if mode == "strategies":
        print("[*] strategies-only 模式：跳过执行日志拉取")
        return strategy_doc, []

    raw_lines = _fetch_log_side(mg, out_dir, now, strategy_doc, max_log_blocks)
    return strategy_doc, raw_lines

# ===========================================================================
# 6. 自检（AES 向量 / GCM 向量 / 通道往返 / ECJPAKE 双端模拟）
# ===========================================================================

def selftest():
    # FIPS-197 A.1 (ECB): key=000102...0f, pt=00112233...eeff -> 69c4e0d8...
    c = _aes_encrypt_block(bytes(range(16)), bytes.fromhex("00112233445566778899aabbccddeeff"))
    assert c.hex() == "69c4e0d86a7b0430d8cdb78070b4c55a", f"AES-128 (FIPS-197 A.1) 自检失败: {c.hex()}"
    # FIPS-197 A.2 (ECB): key=0, pt=0 -> 66e94bd4ef8a2c3b884cfa59ca342b2e
    c2 = _aes_encrypt_block(b"\x00" * 16, b"\x00" * 16)
    assert c2.hex() == "66e94bd4ef8a2c3b884cfa59ca342b2e", f"AES-128 (FIPS-197 A.2) 自检失败: {c2.hex()}"
    print("[selftest] AES-128 (FIPS-197 A.1/A.2) 通过")

    # NIST GCM Test Case 1: K=0^128, IV=0^96, P=空, AAD=空
    ct, tag = aes_gcm_encrypt(b"\x00" * 16, b"\x00" * 12, b"")
    assert ct == b"" and tag.hex() == "58e2fccefa7e3061367f1d57a4e7455a", f"GCM TC1 自检失败: {tag.hex()}"
    # NIST GCM Test Case 2: K=0, IV=0^96, P=0^128, AAD=空（OpenSSL 实测值）
    ct2, tag2 = aes_gcm_encrypt(b"\x00" * 16, b"\x00" * 12, b"\x00" * 16)
    assert ct2.hex() == "0388dace60b6a392f328c2b971b2fe78", f"GCM TC2 密文不符: {ct2.hex()}"
    assert tag2.hex() == "ab6e47d42cec13bdf53a67b21257bddf", f"GCM TC2 标签不符: {tag2.hex()}"
    # 解密往返
    assert aes_gcm_decrypt(b"\x00" * 16, b"\x00" * 12, ct2, tag2) == b"\x00" * 16
    print("[selftest] GCM Test Case 2（密文+标签+解密）通过")

    ch1 = AesGcmChannel(b"\x11" * 16, b"\x22" * 8)
    ch2 = AesGcmChannel(b"\x11" * 16, b"\x22" * 8)
    for data in [b"", b"hi", json.dumps({"jsonrpc": "2.0", "id": 1}).encode()]:
        assert ch2.decrypt(ch1.encrypt(data)) == data
    print("[selftest] AES-GCM 双通道往返通过")

    # ECJPAKE 双端模拟（客户端 + 服务端镜像，验证会话密钥一致）
    import copy
    cli = ECJPAKE("916527", role="client")
    srv = ECJPAKE("916527", role="server")
    srv.read_round_one(cli.write_round_one())
    cli.read_round_one(srv.write_round_one())
    E_cli = cli.read_round_two(srv.write_round_two())
    E_srv = srv.read_round_two(cli.write_round_two())
    assert E_cli == E_srv, f"ECJPAKE 会话密钥不一致: {E_cli.hex()[:16]} vs {E_srv.hex()[:16]}"
    print("[selftest] ECJPAKE 双端模拟会话密钥一致")
    print("[selftest] 全部通过 ✓")


def _mask(pc: str) -> str:
    """登录码脱敏回显：只保留首尾各 2 位。"""
    pc = pc or ""
    if len(pc) <= 4:
        return "*" * len(pc)
    return pc[:2] + "*" * (len(pc) - 4) + pc[-2:]


def get_passcode(initial: str, interactive: bool = True) -> str:
    """失败后重新获取登录码。

    - 交互式（终端）：提示用户输入新登录码，回车沿用旧值；
    - 非交互 / --no-prompt：优先读环境变量 MIJIA_PASSCODE，否则沿用旧值。
    """
    if not interactive:
        return os.environ.get("MIJIA_PASSCODE") or initial
    try:
        entered = input(
            f"获取失败，请重新获取登录码（回车沿用 {_mask(initial)}）: "
        ).strip()
        return entered or initial
    except (EOFError, OSError):
        return os.environ.get("MIJIA_PASSCODE") or initial


# ===========================================================================
# main
# ===========================================================================

def main():
    ap = argparse.ArgumentParser(description="米家极客版中枢网关策略/日志客户端")
    ap.add_argument("--host", default="192.168.31.1")
    ap.add_argument("--port", type=int, default=8086)
    ap.add_argument("--passcode", default=os.environ.get("MIJIA_PASSCODE"),
                    help="网关登录码（也可用环境变量 MIJIA_PASSCODE）")
    ap.add_argument("--out-dir", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "mijia_gw_out"))
    ap.add_argument("--max-log-blocks", type=int, default=6,
                    help="getLog 最大翻页数（默认 6）")
    ap.add_argument("--logs-only", action="store_true",
                    help="仅拉执行日志（不抓策略图/设备/变量表；优先复用已有 mijia_strategies.json 翻译名字）")
    ap.add_argument("--strategies-only", action="store_true",
                    help="仅抓策略/设备/变量表 + 框图，不拉执行日志")
    ap.add_argument("--no-prompt", action="store_true",
                    help="非交互：失败后不提示输入，直接读 MIJIA_PASSCODE 或沿用旧登录码")
    ap.add_argument("--reparse", action="store_true",
                    help="不连网关：用 out-dir 下已有的 raw 日志+策略重新生成 logs.txt")
    ap.add_argument("--enrich", action="store_true",
                    help="不连网关：给 out-dir 下已有的 strategies.json 就地补全实际名字")
    ap.add_argument("--flows", action="store_true",
                    help="不连网关：基于 out-dir 下已有 strategies.json 生成 Mermaid 策略框图")
    ap.add_argument("--selftest", action="store_true", help="仅运行内置密码学自检")
    args = ap.parse_args()

    if args.logs_only and args.strategies_only:
        ap.error("--logs-only 与 --strategies-only 不能同时使用")

    if args.selftest:
        selftest()
        return

    if args.flows:
        write_flows_from_file(os.path.join(args.out_dir, "mijia_strategies.json"), args.out_dir)
        return

    if args.reparse:
        reparse_logs(args.out_dir)
        return

    if args.enrich:
        enrich_strategies_file(os.path.join(args.out_dir, "mijia_strategies.json"))
        return

    if not args.passcode:
        ap.error("需要登录码: --passcode 或环境变量 MIJIA_PASSCODE")

    # 交互式判定：stdin 是终端才算可交互
    interactive = not args.no_prompt and sys.stdin.isatty()
    passcode = args.passcode
    last_err = None
    for attempt in range(1, 4):
        mg = MijiaGateway(args.host, args.port, passcode)
        try:
            mg.connect()
            mode = "logs" if args.logs_only else ("strategies" if args.strategies_only else "all")
            fetch_all(mg, args.out_dir, args.max_log_blocks, mode=mode)
            mg.ws.close()
            print("[*] 完成")
            return
        except (ConnectionError, ValueError) as e:
            last_err = e
            mg.ws.close()
            if attempt < 3:
                print(f"[warn] 第 {attempt} 次获取失败（{e}）")
                # 失败后重新获取登录码，冷却 30s 再试
                passcode = get_passcode(passcode, interactive=interactive)
                print(f"[*] 已（重新）使用登录码 {_mask(passcode)}，等待 30s 冷却后重试 ...")
                time.sleep(30)
        except Exception as e:
            last_err = e
            mg.ws.close()
            print(f"[error] 抓取失败（非认证类，不再重试）: {e}", file=sys.stderr)
            return
    print(f"[error] 重试 3 次仍失败: {last_err}", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
