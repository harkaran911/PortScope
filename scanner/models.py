from django.db import models
import json


class ScanSession(models.Model):
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("running", "Running"),
        ("completed", "Completed"),
        ("failed", "Failed"),
    ]

    SCAN_TYPE_CHOICES = [
        ("quick", "Quick Scan"),
        ("common", "Common Ports"),
        ("full", "Full Scan"),
        ("custom", "Custom Range"),
        ("vuln", "Vulnerability Scan"),
        ("stealth", "Stealth Scan"),
    ]

    target = models.CharField(max_length=255)
    resolved_ip = models.GenericIPAddressField(null=True, blank=True)
    hostname = models.CharField(max_length=255, blank=True)
    scan_type = models.CharField(max_length=20, choices=SCAN_TYPE_CHOICES, default="common")
    port_range_start = models.IntegerField(default=1)
    port_range_end = models.IntegerField(default=1024)
    custom_ports = models.CharField(max_length=500, blank=True)
    timeout = models.FloatField(default=1.0)
    threads = models.IntegerField(default=100)

    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    progress = models.IntegerField(default=0)
    error_message = models.TextField(blank=True)

    open_ports_count = models.IntegerField(default=0)
    closed_ports_count = models.IntegerField(default=0)
    filtered_ports_count = models.IntegerField(default=0)
    risk_score = models.FloatField(default=0.0)

    os_guess = models.CharField(max_length=200, blank=True)
    whois_data = models.TextField(blank=True)
    dns_info = models.TextField(blank=True)
    geo_info = models.TextField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    duration_seconds = models.FloatField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"Scan({self.target}, {self.scan_type}, {self.status})"

    @property
    def dns_info_dict(self):
        try:
            return json.loads(self.dns_info) if self.dns_info else {}
        except Exception:
            return {}

    @property
    def geo_info_dict(self):
        try:
            return json.loads(self.geo_info) if self.geo_info else {}
        except Exception:
            return {}

    @property
    def risk_label(self):
        if self.risk_score >= 7:
            return "Critical"
        elif self.risk_score >= 5:
            return "High"
        elif self.risk_score >= 3:
            return "Medium"
        elif self.risk_score > 0:
            return "Low"
        return "None"

    @property
    def risk_color(self):
        if self.risk_score >= 7:
            return "danger"
        elif self.risk_score >= 5:
            return "warning"
        elif self.risk_score >= 3:
            return "info"
        return "success"


class PortResult(models.Model):
    STATE_CHOICES = [
        ("open", "Open"),
        ("closed", "Closed"),
        ("filtered", "Filtered"),
        ("open|filtered", "Open|Filtered"),
    ]

    RISK_CHOICES = [
        ("critical", "Critical"),
        ("high", "High"),
        ("medium", "Medium"),
        ("low", "Low"),
        ("info", "Info"),
    ]

    PROTOCOL_CHOICES = [
        ("tcp", "TCP"),
        ("udp", "UDP"),
    ]

    session = models.ForeignKey(ScanSession, on_delete=models.CASCADE, related_name="ports")
    port = models.IntegerField()
    protocol = models.CharField(max_length=5, choices=PROTOCOL_CHOICES, default="tcp")
    state = models.CharField(max_length=15, choices=STATE_CHOICES)
    service = models.CharField(max_length=100, blank=True)
    version = models.CharField(max_length=200, blank=True)
    banner = models.TextField(blank=True)
    risk_level = models.CharField(max_length=10, choices=RISK_CHOICES, default="info")
    risk_notes = models.TextField(blank=True)
    response_time_ms = models.FloatField(null=True, blank=True)
    http_title = models.CharField(max_length=300, blank=True)
    http_headers = models.TextField(blank=True)
    ssl_info = models.TextField(blank=True)
    cve_hints = models.TextField(blank=True)

    class Meta:
        ordering = ["port"]
        unique_together = ["session", "port", "protocol"]

    def __str__(self):
        return f"{self.port}/{self.protocol} ({self.state})"

    @property
    def http_headers_dict(self):
        try:
            return json.loads(self.http_headers) if self.http_headers else {}
        except Exception:
            return {}

    @property
    def ssl_info_dict(self):
        try:
            return json.loads(self.ssl_info) if self.ssl_info else {}
        except Exception:
            return {}

    @property
    def cve_hints_list(self):
        try:
            return json.loads(self.cve_hints) if self.cve_hints else []
        except Exception:
            return []

    @property
    def risk_badge_class(self):
        return {
            "critical": "badge-danger",
            "high": "badge-warning",
            "medium": "badge-info",
            "low": "badge-secondary",
            "info": "badge-light",
        }.get(self.risk_level, "badge-light")
