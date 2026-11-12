#!/usr/bin/env python3
"""Fetch public proxy feeds, verify each node end-to-end via sing-box, and output working links."""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path

DEFAULT_SOURCES = [
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Sub1.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Sub2.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/all_extracted_configs.txt",
]

TEST_URL = "https://www.gstatic.com/generate_204"
SUPPORTED_SS_METHODS = {
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
}


def decode_b64(data: str) -> str | None:
    try:
        cleaned = data.strip().replace("-", "+").replace("_", "/")
        pad = len(cleaned) % 4
        if pad:
            cleaned += "=" * (4 - pad)
        return base64.b64decode(cleaned).decode("utf-8", errors="strict")
    except Exception:
        return None


def fetch_text(url: str, timeout: int = 12) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "v2rayN/6.42"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="ignore")


def parse_link_to_outbound(link: str) -> tuple[str, dict] | None:
    link = link.strip()
    if not link or link.startswith("#"):
        return None

    try:
        if link.startswith("ss://"):
            return _parse_ss(link)
        if link.startswith("vless://"):
            return _parse_vless(link)
        if link.startswith("trojan://"):
            return _parse_trojan(link)
        if link.startswith(("hy2://", "hysteria2://")):
            return _parse_hy2(link)
        if link.startswith("vmess://"):
            return _parse_vmess(link)
    except Exception:
        return None
    return None


def _parse_ss(link: str) -> tuple[str, dict] | None:
    raw = link[5:].split("#", 1)[0]
    if "@" not in raw:
        decoded = decode_b64(raw)
        if not decoded or "@" not in decoded:
            return None
        user_part, host_and_q = decoded.split("@", 1)
    else:
        user_enc, host_and_q = raw.split("@", 1)
        user_part = decode_b64(user_enc) or user_enc

    if "?" in host_and_q:
        host_part, query_str = host_and_q.split("?", 1)
        if "plugin=" in query_str.lower():
            return None
    else:
        host_part = host_and_q
    host_part = host_part.split("/", 1)[0]

    if ":" not in user_part or ":" not in host_part:
        return None
    method, password = user_part.split(":", 1)
    if method not in SUPPORTED_SS_METHODS:
        return None

    host, port_s = host_part.rsplit(":", 1)
    host = host.strip("[]")
    port = int(port_s)
    if not host or not (1 <= port <= 65535):
        return None

    return f"ss:{host}:{port}", {
        "type": "shadowsocks",
        "tag": "proxy",
        "server": host,
        "server_port": port,
        "method": method,
        "password": password,
    }


def _apply_transport(node: dict, q: dict[str, list[str]]) -> bool:
    net = q.get("type", ["tcp"])[0].lower()
    if net == "ws":
        ws = {"type": "ws", "path": urllib.parse.unquote(q.get("path", ["/"])[0]) or "/"}
        ws_host = urllib.parse.unquote(q.get("host", [""])[0] or q.get("sni", [""])[0])
        if ws_host:
            ws["headers"] = {"Host": ws_host}
        node["transport"] = ws
    elif net == "grpc":
        svc = urllib.parse.unquote(q.get("serviceName", [""])[0] or q.get("path", [""])[0])
        node["transport"] = {"type": "grpc", "service_name": svc}
    elif net not in ("tcp", ""):
        return False
    return True


def _parse_vless(link: str) -> tuple[str, dict] | None:
    u = urllib.parse.urlparse(link)
    if not u.hostname or not u.port or not u.username:
        return None
    q = urllib.parse.parse_qs(u.query)
    node: dict = {
        "type": "vless",
        "tag": "proxy",
        "server": u.hostname,
        "server_port": u.port,
        "uuid": u.username,
    }
    flow = q.get("flow", [""])[0]
    if flow:
        node["flow"] = flow

    sec = q.get("security", ["none"])[0].lower()
    sni = q.get("sni", [""])[0] or q.get("host", [""])[0] or u.hostname
    insecure = q.get("allowInsecure", ["0"])[0] in ("1", "true") or q.get("insecure", ["0"])[0] in ("1", "true")
    if sec == "reality":
        pbk = q.get("pbk", [""])[0]
        if not pbk:
            return None
        node["tls"] = {
            "enabled": True,
            "server_name": sni,
            "reality": {"enabled": True, "public_key": pbk, "short_id": q.get("sid", [""])[0]},
            "utls": {"enabled": True, "fingerprint": q.get("fp", ["chrome"])[0] or "chrome"},
        }
    elif sec == "tls":
        tls = {"enabled": True, "server_name": sni}
        if insecure:
            tls["insecure"] = True
        node["tls"] = tls

    if not _apply_transport(node, q):
        return None
    return f"vless:{u.hostname}:{u.port}", node


def _parse_trojan(link: str) -> tuple[str, dict] | None:
    u = urllib.parse.urlparse(link)
    if not u.hostname or not u.port or not u.username:
        return None
    q = urllib.parse.parse_qs(u.query)
    sni = q.get("sni", [""])[0] or q.get("host", [""])[0] or u.hostname
    insecure = q.get("allowInsecure", ["0"])[0] in ("1", "true") or q.get("insecure", ["0"])[0] in ("1", "true")
    tls: dict = {"enabled": True, "server_name": sni}
    if insecure:
        tls["insecure"] = True
    node: dict = {
        "type": "trojan",
        "tag": "proxy",
        "server": u.hostname,
        "server_port": u.port,
        "password": urllib.parse.unquote(u.username),
        "tls": tls,
    }
    if not _apply_transport(node, q):
        return None
    return f"trojan:{u.hostname}:{u.port}", node


def _parse_hy2(link: str) -> tuple[str, dict] | None:
    norm = "hysteria2" + link[3:] if link.startswith("hy2://") else link
    u = urllib.parse.urlparse(norm)
    if not u.hostname or not u.port or not u.username:
        return None
    q = urllib.parse.parse_qs(u.query)
    tls: dict = {"enabled": True, "server_name": q.get("sni", [""])[0] or u.hostname}
    if q.get("insecure", ["0"])[0] in ("1", "true") or q.get("allowInsecure", ["0"])[0] in ("1", "true"):
        tls["insecure"] = True
    return f"hy2:{u.hostname}:{u.port}", {
        "type": "hysteria2",
        "tag": "proxy",
        "server": u.hostname,
        "server_port": u.port,
        "password": urllib.parse.unquote(u.username),
        "tls": tls,
    }


def _parse_vmess(link: str) -> tuple[str, dict] | None:
    raw = decode_b64(link[8:])
    if not raw:
        return None
    data = json.loads(raw)
    host = data.get("add", "")
    port = int(data.get("port", 0))
    uuid = data.get("id", "")
    if not host or not (1 <= port <= 65535) or not uuid:
        return None
    node: dict = {
        "type": "vmess",
        "tag": "proxy",
        "server": host,
        "server_port": port,
        "uuid": uuid,
        "security": "auto",
        "alter_id": int(data.get("aid", 0) or 0),
    }
    if str(data.get("tls", "")).lower() == "tls":
        node["tls"] = {"enabled": True, "server_name": data.get("host") or host}
    net = str(data.get("net", "tcp")).lower()
    if net == "ws":
        ws = {"type": "ws", "path": data.get("path") or "/"}
        if data.get("host"):
            ws["headers"] = {"Host": data["host"]}
        node["transport"] = ws
    elif net not in ("tcp", ""):
        return None
    return f"vmess:{host}:{port}", node


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def verify_node(singbox_bin: str, link: str, outbound: dict, timeout_s: float = 5.0) -> tuple[float, str] | None:
    port = free_port()
    cfg = {
        "log": {"level": "panic"},
        "inbounds": [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": port}],
        "outbounds": [outbound],
    }
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg_path = os.path.join(tmpdir, "cfg.json")
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f)

        proc = subprocess.Popen(
            [singbox_bin, "run", "-c", cfg_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            # Wait briefly for local port bind
            deadline = time.monotonic() + 1.5
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    return None
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        break
                except OSError:
                    time.sleep(0.05)
            else:
                return None

            t0 = time.monotonic()
            res = subprocess.run(
                ["curl", "-sS", "-m", str(int(timeout_s)), "-x", f"http://127.0.0.1:{port}", "-o", os.devnull, "-w", "%{http_code}", TEST_URL],
                capture_output=True,
                text=True,
                timeout=timeout_s + 2,
            )
            elapsed_ms = (time.monotonic() - t0) * 1000.0
            if res.returncode == 0 and res.stdout.strip() in ("200", "204"):
                return elapsed_ms, link
            return None
        except Exception:
            return None
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                proc.kill()


def extract_country_hint(link: str) -> str:
    frag = urllib.parse.unquote(link.split("#", 1)[1]) if "#" in link else ""
    m = re.search(r"[\U0001F1E6-\U0001F1FF]{2}", frag)
    if m:
        return m.group(0)
    m2 = re.search(r"\b([A-Z]{2})\b", frag.upper())
    return m2.group(1) if m2 else "OTHER"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--singbox", required=True, help="Path to sing-box binary")
    parser.add_argument("--output", default="vpn-servers.txt", help="Output .txt path")
    parser.add_argument("--max-candidates", type=int, default=250, help="Max candidates to probe")
    parser.add_argument("--max-output", type=int, default=60, help="Max verified links to keep")
    parser.add_argument("--per-country", type=int, default=3, help="Max links per country tag")
    parser.add_argument("--workers", type=int, default=20, help="Concurrent probe workers")
    args = parser.parse_args()

    if not shutil.which(args.singbox) and not Path(args.singbox).is_file():
        print(f"sing-box binary not found: {args.singbox}", file=sys.stderr)
        return 1

    env_sources = os.environ.get("SUBSCRIPTION_SOURCES", "").strip()
    sources = [s.strip() for s in env_sources.splitlines() if s.strip()] if env_sources else DEFAULT_SOURCES

    candidates: list[tuple[str, dict]] = []
    seen_keys: set[str] = set()

    for url in sources:
        try:
            raw = fetch_text(url)
            if "://" not in raw:
                raw = decode_b64(raw) or raw
            for line in raw.splitlines():
                line = line.strip()
                parsed = parse_link_to_outbound(line)
                if not parsed:
                    continue
                key, outbound = parsed
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                candidates.append((line, outbound))
                if len(candidates) >= args.max_candidates:
                    break
        except Exception as exc:
            print(f"Warning: failed to fetch {url}: {exc}", file=sys.stderr)
        if len(candidates) >= args.max_candidates:
            break

    print(f"Probing {len(candidates)} candidate nodes with {args.workers} workers...")
    verified: list[tuple[float, str]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futs = [pool.submit(verify_node, args.singbox, link, ob) for link, ob in candidates]
        for fut in concurrent.futures.as_completed(futs):
            res = fut.result()
            if res:
                verified.append(res)

    verified.sort(key=lambda x: x[0])

    selected: list[str] = []
    per_country_count: dict[str, int] = {}
    for _, link in verified:
        tag = extract_country_hint(link)
        if per_country_count.get(tag, 0) >= args.per_country:
            continue
        per_country_count[tag] = per_country_count.get(tag, 0) + 1
        selected.append(link)
        if len(selected) >= args.max_output:
            break

    if not selected:
        print("No working nodes found during this run; keeping existing output file.", file=sys.stderr)
        return 0

    Path(args.output).write_text("\n".join(selected) + "\n", encoding="utf-8")
    print(f"Wrote {len(selected)} verified nodes to {args.output}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
