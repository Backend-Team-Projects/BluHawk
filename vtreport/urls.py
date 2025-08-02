from django.urls import path
from .views import *

urlpatterns = [
    path("file_report/", VirusTotalReportView.as_view(), name="get_report"),
]
