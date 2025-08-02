
from django.urls import path
from dashboard.views import *

urlpatterns = [
    path('my_intel_search/', MyIntel.as_view(), name = 'my_intel_search'),
    path('subscribe/', Subscribe.as_view(),),
    path('admin_data_refresh/', DBRefresh.as_view(), name = 'db_refresh'),
    path("company_profile/", CompanyProfileSearch.as_view(), name="company_profile"),
    path("cpe_search/", SearchVendorOrProduct.as_view(), name="cpe_search"),
    path("FindIntelFullScan/", FindIntelFullScan.as_view(), name="find_intel_full_scan"),

    # path('find_intel/', FindIntel.as_view(), name = 'find_intel'),
    # path('wapiti_scan/', WapitiVulScanning.as_view(), name = 'wapiti_scan'),
    # path('port_scan/', PortScanning.as_view(), name = 'port_scan'),
    # path('subdomain_search/', SubdomainSearch.as_view(), name = 'subdomain_search'),
    # path('full_subdomain_search/', FullSubdomainSearch.as_view(), name = 'full_subdomain_search'),
]