import json
import threading

from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse, HttpResponse
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone

from .models import ScanSession, PortResult
from .utils.scanner import resolve_target, collect_dns_info, PortScanner
from .utils.service_db import get_ports_for_scan_type


# ── Dashboard ─────────────────────────────────────────────────────────────────

def index(request):
    recent_scans = ScanSession.objects.all()[:10]
    stats = {
        "total_scans": ScanSession.objects.count(),
        "completed": ScanSession.objects.filter(status="completed").count(),
        "running": ScanSession.objects.filter(status="running").count(),
        "critical_finds": ScanSession.objects.filter(risk_score__gte=7).count(),
    }
    return render(request, "scanner/index.html", {"recent_scans": recent_scans, "stats": stats})


# ── Start scan ────────────────────────────────────────────────────────────────

@require_POST
def start_scan(request):
    target = request.POST.get("target", "").strip()
    scan_type = request.POST.get("scan_type", "common")
    timeout = float(request.POST.get("timeout", "1.0"))
    threads = int(request.POST.get("threads", "100"))
    custom_ports = request.POST.get("custom_ports", "")

    if not target:
        return JsonResponse({"error": "Target is required"}, status=400)

    resolution = resolve_target(target)
    if resolution["error"]:
        return JsonResponse({"error": f"Cannot resolve target: {resolution['error']}"}, status=400)

    # Collect DNS info
    dns_info = collect_dns_info(resolution["hostname"] or target, resolution["ip"])

    session = ScanSession.objects.create(
        target=target,
        resolved_ip=resolution["ip"],
        hostname=resolution["hostname"],
        scan_type=scan_type,
        timeout=min(max(timeout, 0.2), 5.0),
        threads=min(max(threads, 1), 300),
        custom_ports=custom_ports,
        dns_info=json.dumps(dns_info),
    )

    # Run scan in background thread
    scanner = PortScanner(session)
    t = threading.Thread(target=_run_scan_safe, args=(scanner,), daemon=True)
    t.start()

    return JsonResponse({"session_id": session.id, "redirect": f"/scan/{session.id}/"})


def _run_scan_safe(scanner):
    try:
        scanner.run()
    except Exception as e:
        session = scanner.session
        session.status = "failed"
        session.error_message = str(e)
        session.save(update_fields=["status", "error_message"])


# ── Scan detail page ──────────────────────────────────────────────────────────

def scan_detail(request, pk):
    session = get_object_or_404(ScanSession, pk=pk)
    ports = session.ports.all()
    open_ports = ports.filter(state="open")

    risk_breakdown = {
        "critical": open_ports.filter(risk_level="critical").count(),
        "high": open_ports.filter(risk_level="high").count(),
        "medium": open_ports.filter(risk_level="medium").count(),
        "low": open_ports.filter(risk_level="low").count(),
        "info": open_ports.filter(risk_level="info").count(),
    }

    return render(request, "scanner/scan_detail.html", {
        "session": session,
        "open_ports": open_ports,
        "risk_breakdown": risk_breakdown,
        "dns_info": session.dns_info_dict,
    })


# ── AJAX: poll scan status ────────────────────────────────────────────────────

def scan_status(request, pk):
    session = get_object_or_404(ScanSession, pk=pk)
    return JsonResponse({
        "status": session.status,
        "progress": session.progress,
        "open": session.open_ports_count,
        "closed": session.closed_ports_count,
        "filtered": session.filtered_ports_count,
        "risk_score": session.risk_score,
        "risk_label": session.risk_label,
        "error": session.error_message,
        "duration": session.duration_seconds,
    })


# ── AJAX: live ports feed ─────────────────────────────────────────────────────

def scan_ports_json(request, pk):
    session = get_object_or_404(ScanSession, pk=pk)
    ports = list(session.ports.filter(state="open").values(
        "port", "protocol", "state", "service", "version",
        "banner", "risk_level", "risk_notes", "response_time_ms",
        "http_title", "ssl_info", "cve_hints",
    ))
    return JsonResponse({"ports": ports, "total": len(ports)})


# ── Report page ───────────────────────────────────────────────────────────────

def report(request, pk):
    session = get_object_or_404(ScanSession, pk=pk)
    open_ports = session.ports.filter(state="open")
    risk_breakdown = {
        "critical": open_ports.filter(risk_level="critical").count(),
        "high": open_ports.filter(risk_level="high").count(),
        "medium": open_ports.filter(risk_level="medium").count(),
        "low": open_ports.filter(risk_level="low").count(),
        "info": open_ports.filter(risk_level="info").count(),
    }
    return render(request, "scanner/report.html", {
        "session": session,
        "open_ports": open_ports,
        "risk_breakdown": risk_breakdown,
        "dns_info": session.dns_info_dict,
    })


# ── Export JSON ───────────────────────────────────────────────────────────────

def export_json(request, pk):
    session = get_object_or_404(ScanSession, pk=pk)
    data = {
        "scan": {
            "id": session.id,
            "target": session.target,
            "resolved_ip": session.resolved_ip,
            "hostname": session.hostname,
            "scan_type": session.scan_type,
            "status": session.status,
            "risk_score": session.risk_score,
            "risk_label": session.risk_label,
            "open_ports": session.open_ports_count,
            "closed_ports": session.closed_ports_count,
            "filtered_ports": session.filtered_ports_count,
            "created_at": str(session.created_at),
            "completed_at": str(session.completed_at),
            "duration_seconds": session.duration_seconds,
            "dns_info": session.dns_info_dict,
            "os_guess": session.os_guess,
        },
        "ports": [],
    }
    for p in session.ports.filter(state="open"):
        data["ports"].append({
            "port": p.port,
            "protocol": p.protocol,
            "state": p.state,
            "service": p.service,
            "version": p.version,
            "banner": p.banner,
            "risk_level": p.risk_level,
            "risk_notes": p.risk_notes,
            "response_time_ms": p.response_time_ms,
            "http_title": p.http_title,
            "ssl_info": p.ssl_info_dict,
            "cve_hints": p.cve_hints_list,
        })
    response = HttpResponse(json.dumps(data, indent=2), content_type="application/json")
    response["Content-Disposition"] = f'attachment; filename="portscope-{session.id}.json"'
    return response


# ── Export CSV ────────────────────────────────────────────────────────────────

def export_csv(request, pk):
    import csv
    session = get_object_or_404(ScanSession, pk=pk)
    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = f'attachment; filename="portscope-{session.id}.csv"'
    writer = csv.writer(response)
    writer.writerow(["Port", "Protocol", "State", "Service", "Version", "Risk", "Notes", "Response (ms)", "HTTP Title", "CVEs"])
    for p in session.ports.filter(state="open"):
        writer.writerow([
            p.port, p.protocol, p.state, p.service, p.version,
            p.risk_level, p.risk_notes, p.response_time_ms,
            p.http_title, "; ".join(p.cve_hints_list),
        ])
    return response


# ── Delete scan ───────────────────────────────────────────────────────────────

@require_POST
def delete_scan(request, pk):
    session = get_object_or_404(ScanSession, pk=pk)
    session.delete()
    return JsonResponse({"ok": True})


# ── History ───────────────────────────────────────────────────────────────────

def history(request):
    scans = ScanSession.objects.all()
    return render(request, "scanner/history.html", {"scans": scans})
