"""Low-level network probes: unprivileged ICMP echo, UDP DNS A/TXT queries, SO_BINDTODEVICE, and `ip -j` wrappers."""

from __future__ import annotations

import json
import os
import random
import shutil
import socket
import statistics
import struct
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Callable

SAFE_PATH_ENV = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
SO_BINDTODEVICE = getattr(socket, "SO_BINDTODEVICE", 25)


def _cmd_env() -> dict[str, str]:
    return {"LC_ALL": "C", "PATH": os.environ.get("PATH") or SAFE_PATH_ENV}


def bind_to_device(sock: socket.socket, iface: str | None) -> bool:
    """Bind socket to network interface name via SO_BINDTODEVICE. Returns True if bound."""
    if not iface:
        return False
    try:
        sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, iface.encode("ascii") + b"\x00")
        return True
    except OSError:
        return False


@dataclass(frozen=True)
class IcmpResult:
    ok: bool
    min_ms: float | None
    median_ms: float | None
    via_tunnel: bool = False


def icmp_echo_probe(
    host_or_ip: str,
    *,
    count: int = 3,
    interval_s: float = 0.2,
    timeout_s: float = 1.0,
    bind_iface: str | None = None,
) -> IcmpResult:
    """Unprivileged ICMP echo probe using SOCK_DGRAM + IPPROTO_ICMP."""
    try:
        infos = socket.getaddrinfo(host_or_ip, None, socket.AF_INET, socket.SOCK_DGRAM)
        if not infos:
            return IcmpResult(ok=False, min_ms=None, median_ms=None)
        target_ip = str(infos[0][4][0])
    except OSError:
        return IcmpResult(ok=False, min_ms=None, median_ms=None)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
    except OSError:
        # Unprivileged ICMP disabled by net.ipv4.ping_group_range
        return IcmpResult(ok=False, min_ms=None, median_ms=None)

    via_tunnel = False
    try:
        if bind_iface:
            if not bind_to_device(sock, bind_iface):
                via_tunnel = True
        sock.settimeout(timeout_s)
        rtts: list[float] = []
        ident = random.randint(1, 0xFFFF)
        payload = b"SSULPING"

        for seq in range(1, count + 1):
            pkt = struct.pack("!BBHHH", 8, 0, 0, ident, seq) + payload
            t0 = time.monotonic()
            try:
                sock.sendto(pkt, (target_ip, 0))
                while True:
                    rem = timeout_s - (time.monotonic() - t0)
                    if rem <= 0:
                        break
                    sock.settimeout(rem)
                    data, _ = sock.recvfrom(1024)
                    if len(data) >= 8:
                        rtype, rcode, _ck, _rid, rseq = struct.unpack("!BBHHH", data[:8])
                        if rtype == 0 and rcode == 0 and rseq == seq:
                            rtts.append((time.monotonic() - t0) * 1000.0)
                            break
            except OSError:
                pass
            if seq < count and interval_s > 0:
                time.sleep(interval_s)

        if not rtts:
            return IcmpResult(ok=False, min_ms=None, median_ms=None, via_tunnel=via_tunnel)
        return IcmpResult(
            ok=True,
            min_ms=round(min(rtts), 2),
            median_ms=round(statistics.median(rtts), 2),
            via_tunnel=via_tunnel,
        )
    finally:
        sock.close()


def _encode_dns_name(qname: str) -> bytes:
    parts = [p for p in qname.strip(".").split(".") if p]
    out = bytearray()
    for p in parts:
        b = p.encode("ascii")
        out.append(len(b))
        out.extend(b)
    out.append(0)
    return bytes(out)


def _skip_dns_name(buf: bytes, offset: int) -> int:
    while offset < len(buf):
        length = buf[offset]
        if length == 0:
            return offset + 1
        if (length & 0xC0) == 0xC0:
            return offset + 2
        offset += 1 + length
    return offset


def _build_dns_query(qname: str, qtype: int) -> tuple[int, bytes]:
    txid = random.randint(1, 0xFFFF)
    # Standard recursive query (RD=1 -> 0x0100), QDCOUNT=1
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    question = _encode_dns_name(qname) + struct.pack("!HH", qtype, 1)
    return txid, header + question


def dns_udp_query(
    qname: str,
    server_ip: str = "162.252.172.57",
    *,
    qtype: int = 1,  # 1 = A, 16 = TXT
    timeout_s: float = 2.0,
    bind_iface: str | None = None,
) -> tuple[bool, list[str], float]:
    """Perform a raw DNS-over-UDP query for A (1) or TXT (16) records. Returns (ok, records, rtt_ms)."""
    txid, req_pkt = _build_dns_query(qname, qtype)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        if bind_iface:
            if not bind_to_device(sock, bind_iface):
                return False, [], 0.0
        sock.settimeout(timeout_s)
        t0 = time.monotonic()
        sock.sendto(req_pkt, (server_ip, 53))
        resp, _ = sock.recvfrom(2048)
        rtt_ms = (time.monotonic() - t0) * 1000.0
    except OSError:
        return False, [], 0.0
    finally:
        sock.close()

    if len(resp) < 12:
        return False, [], rtt_ms
    r_txid, flags, qdcount, ancount, _ns, _ar = struct.unpack("!HHHHHH", resp[:12])
    if r_txid != txid or (flags & 0x8000) == 0:
        return False, [], rtt_ms
    rcode = flags & 0x000F
    if rcode != 0:
        return False, [], rtt_ms

    off = 12
    for _ in range(qdcount):
        off = _skip_dns_name(resp, off) + 4

    records: list[str] = []
    for _ in range(ancount):
        if off >= len(resp):
            break
        off = _skip_dns_name(resp, off)
        if off + 10 > len(resp):
            break
        rtype, rclass, _ttl, rdlen = struct.unpack("!HHIH", resp[off : off + 10])
        off += 10
        if off + rdlen > len(resp):
            break
        rdata = resp[off : off + rdlen]
        off += rdlen
        if rclass != 1:
            continue
        if rtype == 1 and rdlen == 4:
            records.append(socket.inet_ntoa(rdata))
        elif rtype == 16 and rdlen >= 1:
            idx = 0
            txt_parts: list[str] = []
            while idx < len(rdata):
                tlen = rdata[idx]
                idx += 1
                txt_parts.append(rdata[idx : idx + tlen].decode("utf-8", errors="replace"))
                idx += tlen
            records.append("".join(txt_parts))

    return True, records, round(rtt_ms, 2)


def run_ip_json(args: list[str], which_fn: Callable[[str], str | None] = shutil.which) -> Any:
    """Execute `ip -j <args>` and parse JSON output."""
    ip_bin = which_fn("ip")
    if not ip_bin:
        return None
    try:
        res = subprocess.run(
            [ip_bin, "-j"] + args,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=2.0,
            shell=False,
            env=_cmd_env(),
        )
        if res.returncode != 0 or not res.stdout:
            return None
        return json.loads(res.stdout.decode("utf-8", errors="replace"))
    except Exception:
        return None


@dataclass(frozen=True)
class RouteLookup:
    dev: str | None
    prefsrc: str | None
    gateway: str | None


def route_get(dest: str = "8.8.8.8", ipv6: bool = False) -> RouteLookup:
    args = (["-6"] if ipv6 else []) + ["route", "get", dest]
    data = run_ip_json(args)
    if isinstance(data, list) and data and isinstance(data[0], dict):
        row = data[0]
        return RouteLookup(
            dev=row.get("dev") if isinstance(row.get("dev"), str) else None,
            prefsrc=row.get("prefsrc") if isinstance(row.get("prefsrc"), str) else None,
            gateway=row.get("gateway") if isinstance(row.get("gateway"), str) else None,
        )
    return RouteLookup(dev=None, prefsrc=None, gateway=None)


def get_physical_default_iface(exclude_ifaces: set[str] | None = None) -> str | None:
    """Return the lowest-metric default-route interface in table main excluding VPN interfaces."""
    excluded = set(exclude_ifaces or ()) | {"lo", "surfshark_lite", "surfshark_wg", "surfshark_tun", "surfshark_ipv6"}
    routes = run_ip_json(["route", "show", "table", "main", "default"])
    if not isinstance(routes, list):
        return None
    best_dev: str | None = None
    best_metric: int = 10**9
    for r in routes:
        if not isinstance(r, dict):
            continue
        dev = r.get("dev")
        if not isinstance(dev, str) or dev in excluded or dev.startswith("surfshark"):
            continue
        metric = r.get("metric")
        m_val = int(metric) if isinstance(metric, int) else 100
        if m_val < best_metric:
            best_metric = m_val
            best_dev = dev
    return best_dev


def get_physical_dns_servers(phys_iface: str | None) -> list[str]:
    """Read DNS servers configured on physical interface via `resolvectl dns <iface>`."""
    servers: list[str] = []
    resolvectl_bin = shutil.which("resolvectl")
    if resolvectl_bin and phys_iface:
        try:
            res = subprocess.run(
                [resolvectl_bin, "dns", phys_iface],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=2.0,
                shell=False,
                env=_cmd_env(),
            )
            if res.returncode == 0:
                text = res.stdout.decode("utf-8", errors="replace")
                if ":" in text:
                    rhs = text.split(":", 1)[1]
                    for tok in rhs.split():
                        try:
                            socket.inet_aton(tok)
                            servers.append(tok)
                        except OSError:
                            pass
        except Exception:
            pass
    for fallback in ("1.1.1.1", "8.8.8.8"):
        if fallback not in servers:
            servers.append(fallback)
    return servers


def resolve_ipv4(
    hostname: str,
    *,
    tunnel_stalled: bool = False,
    phys_iface: str | None = None,
) -> str:
    """Resolve hostname to IPv4 address, bypassing a stalled tunnel via physical interface if needed."""
    try:
        socket.inet_aton(hostname)
        return hostname
    except OSError:
        pass

    if not tunnel_stalled:
        try:
            infos = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_DGRAM)
            if infos:
                return str(infos[0][4][0])
        except OSError:
            pass

    p_iface = phys_iface or get_physical_default_iface()
    for dns_ip in get_physical_dns_servers(p_iface):
        ok, addrs, _ = dns_udp_query(hostname, dns_ip, qtype=1, timeout_s=2.0, bind_iface=p_iface)
        if ok and addrs:
            return addrs[0]

    # Final fallback to system getaddrinfo
    infos = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_DGRAM)
    if not infos:
        raise OSError(f"Unable to resolve IPv4 for {hostname}")
    return str(infos[0][4][0])


def query_anycast_pubkey(
    anycast_host: str = "wgs.prod.surfshark.com",
    fallback_pubkey: str = "o07k/2dsaQkLLSR0dCI/FUd3FLik/F/HBBcOGUkNQGo=",
    phys_iface: str | None = None,
) -> str:
    """Query TXT record on wgs.prod.surfshark.com (`[public_key:<b64>]`) per G5."""
    for dns_ip in ("1.1.1.1", "8.8.8.8"):
        ok, txts, _ = dns_udp_query(anycast_host, dns_ip, qtype=16, timeout_s=2.0, bind_iface=phys_iface)
        if ok:
            for t in txts:
                if "public_key:" in t:
                    cleaned = t.replace("[", "").replace("]", "").strip()
                    pub = cleaned.split("public_key:", 1)[1].strip()
                    if len(pub) == 44 and pub.endswith("="):
                        return pub
    return fallback_pubkey


def resolve_ipv4_all(hostname: str, timeout: float = 4.0) -> list[str]:
    """Return all resolved IPv4 addresses for `hostname`, or empty list on failure."""
    try:
        ip = resolve_ipv4(hostname)
        return [ip] if ip else []
    except Exception:
        return []


def lookup_dns_txt_pubkey(hostname: str = "wgs.prod.surfshark.com", timeout: float = 2.0) -> str | None:
    """Query TXT record for WireGuard public_key."""
    return query_anycast_pubkey(anycast_host=hostname)


def run_cmd(args: list[str], timeout: float = 2.0) -> tuple[int, str, str]:
    """Run a command with safe PATH and return (returncode, stdout, stderr)."""
    if not args:
        return 1, "", ""
    bin_path = shutil.which(args[0])
    if not bin_path:
        return 127, "", f"{args[0]}: not found"
    try:
        res = subprocess.run(
            [bin_path] + args[1:],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            shell=False,
            env=_cmd_env(),
        )
        return (
            res.returncode,
            res.stdout.decode("utf-8", errors="replace"),
            res.stderr.decode("utf-8", errors="replace"),
        )
    except Exception as exc:
        return 1, "", str(exc)


def parse_wg_dump(dump_text: str) -> dict[str, Any]:
    """Parse `wg show <iface> dump` tab-separated output."""
    lines = [ln.strip() for ln in dump_text.strip().splitlines() if ln.strip()]
    peers: list[dict[str, Any]] = []
    if len(lines) >= 2:
        for ln in lines[1:]:
            cols = ln.split("\t")
            if len(cols) >= 8:
                peers.append({
                    "public_key": cols[0],
                    "endpoint": None if cols[2] == "(none)" else cols[2],
                    "allowed_ips": cols[3].split(",") if cols[3] != "(none)" else [],
                    "latest_handshake": int(cols[4]) if cols[4].isdigit() else 0,
                    "rx_bytes": int(cols[5]) if cols[5].isdigit() else 0,
                    "tx_bytes": int(cols[6]) if cols[6].isdigit() else 0,
                    "persistent_keepalive": cols[7],
                })
    return {"peers": peers}


def read_proc_net_dev(iface: str) -> tuple[int, int] | None:
    """Read `(rx_bytes, tx_bytes)` for `iface` from `/proc/net/dev`."""
    try:
        with open("/proc/net/dev", "r", encoding="utf-8") as fh:
            for line in fh:
                if ":" not in line:
                    continue
                name, rest = line.split(":", 1)
                if name.strip() == iface:
                    fields = rest.split()
                    if len(fields) >= 9:
                        return int(fields[0]), int(fields[8])
    except OSError:
        pass
    return None

