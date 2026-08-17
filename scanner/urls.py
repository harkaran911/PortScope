from django.urls import path
from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("scan/start/", views.start_scan, name="start_scan"),
    path("scan/<int:pk>/", views.scan_detail, name="scan_detail"),
    path("scan/<int:pk>/status/", views.scan_status, name="scan_status"),
    path("scan/<int:pk>/ports/", views.scan_ports_json, name="scan_ports_json"),
    path("scan/<int:pk>/report/", views.report, name="report"),
    path("scan/<int:pk>/export/json/", views.export_json, name="export_json"),
    path("scan/<int:pk>/export/csv/", views.export_csv, name="export_csv"),
    path("scan/<int:pk>/delete/", views.delete_scan, name="delete_scan"),
    path("history/", views.history, name="history"),
]
