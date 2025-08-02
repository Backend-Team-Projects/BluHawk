
from django.contrib import admin
from django.urls import path
from usage.views import *

urlpatterns = [
    path('get_usage', getUsage.as_view()),
    path("get_paginated_request_logs", GetPaginatedRequestLogs.as_view()),
    path("get_usage_stats/", GetUsageStats.as_view()),
    path("get_usage_stats_by_date", GetTimeFramedLogs.as_view()),
    path("get_paginated_Scan_logs", GetPaginatedScanLogs.as_view()),
]