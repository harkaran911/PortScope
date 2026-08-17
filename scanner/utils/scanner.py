"""Core port scanning engine — pure Python, no root required."""

import socket
import ssl
import json
import time
import struct
import threading
import concurrent.futures
import ipaddress
import http.client
import urllib.request
import urllib.error
from datetime import datetime, timezone

from .service_db import get_service_info, get_ports_for_scan_type


# ── Timeouts and limits ───────────────────────────────────────────────────────
CONNECT_TIMEOUT = 1.5
BANNER_TIMEOUT = 2.0
HTTP_TIMEOUT = 3.0
MAX_BANNER_BYTES = 1024


def resolve_target(target: str) -> dict:
    """Resolve hostname → IP, collect DNS records."""
    result = {"hostname": "", "ip": "", "error": ""}
    target = target.strip()

    try:
        ipaddress.ip_address(target)
        result["ip"] = target
        try:
            result["hostname"] = socket.gethostbyaddr(target)[0]
        except Exception:
            result["hostname"] = target
        return result
    except ValueError:
        pass

    try:
        result["hostname"] = target
        result["ip"] = socket.gethostbyname(target)
        return result
    except socket.gaierror as e:
        result["error"] = str(e)
        return result


def collect_dns_info(hostname: str, ip: str) -> dict:
    info = {"a": [], "ptr": "", "aliases": []}
    try:
        addrs = socket.getaddrinfo(hostname, None)
        info["a"] = list({r[4][0] for r in addrs})
    except Exception:
        if ip:
            info["a"] = [ip]
    try:
        ptr = socket.gethostbyaddr(ip)
        info["ptr"] = ptr[0]
        info["aliases"] = list(ptr[1])
    except Exception:
        pass
    return info


def grab_banner(host: str, port: int, timeout: float = BANNER_TIMEOUT) -> str:
    """Attempt to grab a service banner via raw TCP."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                data = s.recv(MAX_BANNER_BYTES)
                return data.decode("utf-8", errors="replace").strip()
            except Exception:
                pass
            probes = [b"HEAD / HTTP/1.0\r\n\r\n", b"\r\n", b"HELP\r\n", b"VERSION\r\n"]
            for probe in probes:
                try:
                    s.sendall(probe)
                    data = s.recv(MAX_BANNER_BYTES)
                    if data:
                        return data.decode("utf-8", errors="replace").strip()
                except Exception:
                    continue
    except Exception:
        pass
    return ""


def grab_http_info(host: str, port: int, use_ssl: bool = False) -> dict:
    """Grab HTTP headers and page title."""
    result = {"title": "", "headers": {}, "server": "", "status": ""}
    scheme = "https" if use_ssl else "http"
    url = f"{scheme}://{host}:{port}/"
    try:
        ctx = ssl.create_default_context() if use_ssl else None
        if ctx:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": "PortScope/1.0"})
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT, context=ctx) as resp:
            result["status"] = str(resp.status)
            for k, v in resp.headers.items():
                result["headers"][k.lower()] = v
            result["server"] = resp.headers.get("Server", "")
            body = resp.read(8192).decode("utf-8", errors="replace")
            start = body.lower().find("<title>")
            end = body.lower().find("</title>")
            if start != -1 and end != -1:
                result["title"] = body[start + 7:end].strip()[:200]
    except urllib.error.HTTPError as e:
        result["status"] = str(e.code)
        for k, v in e.headers.items():
            result["headers"][k.lower()] = v
        result["server"] = e.headers.get("Server", "")
    except Exception:
        pass
    return result


def grab_ssl_info(host: str, port: int) -> dict:
    """Get SSL/TLS certificate information."""
    result = {}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                cert = s.getpeercert()
                cipher = s.cipher()
                version = s.version()
                result["version"] = version or ""
                result["cipher"] = cipher[0] if cipher else ""
                result["bits"] = cipher[2] if cipher else 0
                if cert:
                    result["subject"] = dict(x[0] for x in cert.get("subject", []))
                    result["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                    result["not_before"] = cert.get("notBefore", "")
                    result["not_after"] = cert.get("notAfter", "")
                    san = cert.get("subjectAltName", [])
                    result["san"] = [v for _, v in san]
                    result["expired"] = False
                    try:
                        exp = datetime.strptime(result["not_after"], "%b %d %H:%M:%S %Y %Z")
                        result["expired"] = exp < datetime.utcnow()
                        result["days_remaining"] = (exp - datetime.utcnow()).days
                    except Exception:
                        pass
    except Exception:
        pass
    return result


def tcp_connect_scan(host: str, port: int, timeout: float) -> dict:
    """TCP connect scan — reliable, works without root."""
    t0 = time.perf_counter()
    result = {
        "port": port,
        "protocol": "tcp",
        "state": "closed",
        "response_time_ms": None,
        "banner": "",
    }
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            elapsed = (time.perf_counter() - t0) * 1000
            result["state"] = "open"
            result["response_time_ms"] = round(elapsed, 2)
    except socket.timeout:
        result["state"] = "filtered"
    except ConnectionRefusedError:
        result["state"] = "closed"
    except OSError:
        result["state"] = "filtered"
    return result


class PortScanner:
    def __init__(self, session):
        self.session = session
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def run(self):
        from scanner.models import PortResult
        from django.utils import timezone as dj_tz

        session = self.session
        host = session.resolved_ip or session.target
        ports = get_ports_for_scan_type(
            session.scan_type,
            session.port_range_start,
            session.port_range_end,
            session.custom_ports,
        )
        total = len(ports)
        scanned = 0
        open_count = 0
        closed_count = 0
        filtered_count = 0
        risk_scores = []

        # Update status to running
        session.status = "running"
        session.progress = 0
        session.save(update_fields=["status", "progress"])

        timeout = session.timeout
        max_workers = min(session.threads, 200)

        def scan_port(port):
            if self._stop.is_set():
                return None
            result = tcp_connect_scan(host, port, timeout)
            return result

        open_ports = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(scan_port, p): p for p in ports}
            for future in concurrent.futures.as_completed(futures):
                if self._stop.is_set():
                    break
                scanned += 1
                res = future.result()
                if res is None:
                    continue

                if res["state"] == "open":
                    open_count += 1
                    open_ports.append(res)
                elif res["state"] == "closed":
                    closed_count += 1
                else:
                    filtered_count += 1

                progress = int((scanned / total) * 85)
                if scanned % 50 == 0 or scanned == total:
                    session.progress = progress
                    session.open_ports_count = open_count
                    session.closed_ports_count = closed_count
                    session.filtered_ports_count = filtered_count
                    session.save(update_fields=["progress", "open_ports_count", "closed_ports_count", "filtered_ports_count"])

        session.progress = 88
        session.save(update_fields=["progress"])

        # Deep analysis of open ports
        port_results = []
        for res in open_ports:
            if self._stop.is_set():
                break
            port = res["port"]
            svc_info = get_service_info(port)
            service_name = svc_info["service"]
            risk = svc_info["risk"]
            notes = svc_info["notes"]
            cve_hints = svc_info.get("cve_hints", [])

            banner = ""
            http_title = ""
            http_headers_json = ""
            ssl_info_json = ""
            version = ""

            # Banner grab
            if session.scan_type in ("vuln", "stealth", "common", "quick", "custom", "full"):
                banner = grab_banner(host, port)

            # HTTP analysis
            is_http_port = port in (80, 8080, 8000, 8008, 8081, 8082, 8083, 8084, 8085, 8088, 8090)
            is_https_port = port in (443, 8443, 4443, 9443)

            if is_http_port or is_https_port:
                http_info = grab_http_info(host, port, use_ssl=is_https_port)
                http_title = http_info.get("title", "")
                headers = http_info.get("headers", {})
                if headers:
                    http_headers_json = json.dumps(headers)
                server = http_info.get("server", "")
                if server:
                    version = server[:200]

            if is_https_port or port in (636, 995, 993, 465):
                ssl_data = grab_ssl_info(host, port)
                if ssl_data:
                    ssl_info_json = json.dumps(ssl_data)
                    if ssl_data.get("expired"):
                        risk = "critical"
                        notes += "; SSL certificate EXPIRED"
                        cve_hints.append("Expired TLS certificate")
                    old_versions = ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")
                    if ssl_data.get("version", "") in old_versions:
                        risk = max(risk, "high") if risk != "critical" else "critical"
                        cve_hints.append(f"Deprecated TLS: {ssl_data['version']}")

            # Infer version from banner
            if banner and not version:
                version = banner[:200]

            risk_map = {"info": 1, "low": 2, "medium": 4, "high": 6, "critical": 9}
            risk_scores.append(risk_map.get(risk, 1))

            port_results.append(PortResult(
                session=session,
                port=port,
                protocol="tcp",
                state="open",
                service=service_name,
                version=version,
                banner=banner[:1000] if banner else "",
                risk_level=risk,
                risk_notes=notes,
                response_time_ms=res.get("response_time_ms"),
                http_title=http_title[:300],
                http_headers=http_headers_json,
                ssl_info=ssl_info_json,
                cve_hints=json.dumps(cve_hints) if cve_hints else "",
            ))

        if port_results:
            PortResult.objects.bulk_create(port_results, ignore_conflicts=True)

        # Risk score = average of top-3 highest risk ports (or all if < 3)
        if risk_scores:
            top = sorted(risk_scores, reverse=True)[:3]
            overall_risk = sum(top) / len(top)
        else:
            overall_risk = 0.0

        session.risk_score = round(overall_risk, 2)
        session.status = "completed"
        session.progress = 100
        session.completed_at = dj_tz.now()
        start_time = session.created_at
        session.duration_seconds = (dj_tz.now() - start_time).total_seconds()
        session.save(update_fields=[
            "risk_score", "status", "progress", "completed_at", "duration_seconds",
        ])
