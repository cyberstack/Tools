#!/usr/bin/env python3
"""host_posture.py — read-only view of what a hostname publishes.

Looks up A/AAAA/MX/NS/TXT/CAA, reads the TLS certificate on 443, and notes a
few HTTPS response headers. Recurses only for the name you passed (plus
_dmarc.<name> for the DMARC TXT). No extra ports, no payloads, no exploit
steps.

Usage:
  python3 host_posture.py example.com
  python3 host_posture.py example.com --timeout 8
"""
from __future__ import annotations

import argparse
import datetime as dt
import socket
import ssl
import struct
import sys
from http.client import HTTPSConnection
from typing import Iterable
from urllib.parse import urlparse

RESOLVERS = ("1.1.1.1", "8.8.8.8")
QTYPES = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28, "CAA": 257}
HEADER_WATCH = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
)


class DnsError(Exception):
    pass


def _encode_name(name: str) -> bytes:
    out = bytearray()
    for label in name.rstrip(".").split("."):
        raw = label.encode("idna")
        if not raw or len(raw) > 63:
            raise DnsError(f"bad label in {name}")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def _read_name(buf: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    jumped = False
    end = offset
    hops = 0
    while True:
        if offset >= len(buf):
            raise DnsError("truncated name")
        length = buf[offset]
        if length == 0:
            offset += 1
            if not jumped:
                end = offset
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(buf):
                raise DnsError("truncated pointer")
            pointer = ((length & 0x3F) << 8) | buf[offset + 1]
            if not jumped:
                end = offset + 2
            offset = pointer
            jumped = True
            hops += 1
            if hops > 10:
                raise DnsError("pointer loop")
            continue
        offset += 1
        chunk = buf[offset : offset + length]
        try:
            labels.append(chunk.decode("idna"))
        except UnicodeError:
            labels.append(chunk.decode("ascii", "replace"))
        offset += length
        if not jumped:
            end = offset
    return ".".join(labels), end


def _query(name: str, qtype: str, timeout: float) -> list[str]:
    qid = 0xC5D1
    payload = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    payload += _encode_name(name) + struct.pack("!HH", QTYPES[qtype], 1)
    last_err: Exception | None = None
    buf = b""
    for resolver in RESOLVERS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(payload, (resolver, 53))
            buf, _ = sock.recvfrom(4096)
            sock.close()
            if len(buf) >= 12:
                last_err = None
                break
        except OSError as exc:
            last_err = exc
            continue
    if last_err is not None or len(buf) < 12:
        raise DnsError(str(last_err) if last_err else "empty DNS reply")
    rcode = buf[3] & 0x0F
    if rcode == 3:
        return []
    if rcode != 0:
        raise DnsError(f"rcode {rcode}")
    qd, an = struct.unpack("!HH", buf[4:8])
    offset = 12
    for _ in range(qd):
        _, offset = _read_name(buf, offset)
        offset += 4
    answers: list[str] = []
    for _ in range(an):
        _, offset = _read_name(buf, offset)
        if offset + 10 > len(buf):
            break
        rtype, _, _, rdlen = struct.unpack("!HHIH", buf[offset : offset + 10])
        offset += 10
        rdata = buf[offset : offset + rdlen]
        offset += rdlen
        if rtype == QTYPES["A"] and len(rdata) == 4:
            answers.append(socket.inet_ntoa(rdata))
        elif rtype == QTYPES["AAAA"] and len(rdata) == 16:
            answers.append(socket.inet_ntop(socket.AF_INET6, rdata))
        elif rtype in (QTYPES["NS"], QTYPES["CNAME"]):
            host, _ = _read_name(buf, offset - rdlen)
            answers.append(host)
        elif rtype == QTYPES["MX"] and len(rdata) >= 3:
            pref = struct.unpack("!H", rdata[:2])[0]
            host, _ = _read_name(buf, offset - rdlen + 2)
            answers.append(f"{pref} {host}")
        elif rtype == QTYPES["TXT"]:
            chunks: list[str] = []
            i = 0
            while i < len(rdata):
                n = rdata[i]
                i += 1
                chunks.append(rdata[i : i + n].decode("utf-8", "replace"))
                i += n
            answers.append("".join(chunks))
        elif rtype == QTYPES["CAA"] and len(rdata) >= 2:
            flags = rdata[0]
            tag_len = rdata[1]
            tag = rdata[2 : 2 + tag_len].decode("ascii", "replace")
            value = rdata[2 + tag_len :].decode("utf-8", "replace")
            answers.append(f"{flags} {tag} {value}")
    return answers


def dns_section(host: str, timeout: float) -> list[str]:
    lines = ["DNS"]
    for qtype in ("A", "AAAA", "MX", "NS", "TXT", "CAA"):
        try:
            rows = _query(host, qtype, timeout)
        except DnsError as exc:
            lines.append(f"  {qtype:4}  (lookup failed: {exc})")
            continue
        if not rows:
            lines.append(f"  {qtype:4}  —")
            continue
        for i, row in enumerate(rows):
            label = qtype if i == 0 else ""
            lines.append(f"  {label:4}  {row}")
    try:
        dmarc = _query(f"_dmarc.{host}", "TXT", timeout)
    except DnsError as exc:
        lines.append(f"  DMARC  (lookup failed: {exc})")
        dmarc = []
    if dmarc:
        for row in dmarc:
            lines.append(f"  DMARC  {row}")
    else:
        lines.append("  DMARC  —")
    spf = [t for t in _safe_txt(host, timeout) if t.lower().startswith("v=spf1")]
    if spf:
        for row in spf:
            lines.append(f"  SPF   {row}")
    else:
        lines.append("  SPF   —")
    return lines


def _safe_txt(host: str, timeout: float) -> list[str]:
    try:
        return _query(host, "TXT", timeout)
    except DnsError:
        return []


def tls_section(host: str, timeout: float) -> list[str]:
    lines = ["TLS :443"]
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as sock:
                cert = sock.getpeercert()
                version = sock.version()
    except ssl.SSLCertVerificationError as exc:
        lines.append(f"  verify failed: {exc.verify_message or exc}")
        return lines
    except OSError as exc:
        lines.append(f"  connect failed: {exc}")
        return lines
    not_after = cert.get("notAfter") or ""
    expiry = None
    if not_after:
        expiry = dt.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=dt.timezone.utc
        )
    now = dt.datetime.now(dt.timezone.utc)
    days = (expiry - now).days if expiry else None
    sans = []
    for kind, value in cert.get("subjectAltName") or []:
        if kind == "DNS":
            sans.append(value)
    subject = " / ".join(v for pair in (cert.get("subject") or []) for _, v in pair)
    issuer = " / ".join(v for pair in (cert.get("issuer") or []) for _, v in pair)
    lines.append(f"  proto    {version}")
    lines.append(f"  subject  {subject or '—'}")
    lines.append(f"  issuer   {issuer or '—'}")
    lines.append(f"  san      {', '.join(sans) if sans else '—'}")
    if days is None:
        lines.append("  expires  —")
    else:
        when = expiry.date().isoformat() if expiry else "—"
        flag = "  (≤14 days)" if days <= 14 else ""
        lines.append(f"  expires  {when}  ({days} days){flag}")
    return lines


def header_section(host: str, timeout: float) -> list[str]:
    lines = ["HTTPS headers"]
    try:
        conn = HTTPSConnection(host, timeout=timeout)
        conn.request("HEAD", "/", headers={"User-Agent": "cyberstack-host-posture/1"})
        resp = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        status = resp.status
        conn.close()
    except OSError as exc:
        lines.append(f"  request failed: {exc}")
        return lines
    lines.append(f"  status   {status}")
    for key in HEADER_WATCH:
        value = headers.get(key)
        lines.append(f"  {key:24}  {value if value else 'missing'}")
    return lines


def parse_host(raw: str) -> str:
    text = raw.strip()
    if "://" in text:
        text = urlparse(text).hostname or text
    return text.strip(".").lower()


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only DNS + TLS + header posture for one hostname."
    )
    parser.add_argument("host", help="hostname, e.g. example.com")
    parser.add_argument("--timeout", type=float, default=8.0)
    args = parser.parse_args(list(argv) if argv is not None else None)
    host = parse_host(args.host)
    if not host or " " in host:
        print("Need a single hostname.", file=sys.stderr)
        return 2
    chunks = [
        dns_section(host, args.timeout),
        tls_section(host, args.timeout),
        header_section(host, args.timeout),
    ]
    print(f"host_posture  {host}")
    print()
    print("\n\n".join("\n".join(c) for c in chunks))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
