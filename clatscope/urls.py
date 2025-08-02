
from django.urls import path
from clatscope.views import *

urlpatterns = [

    path("get_who_is/", WhoIsAPI.as_view(), name="get_who_is"),
    path("get_username/", UserNameCheck.as_view(), name="get_username"),
    path('get_ip_info/', IPInfoAPI.as_view(), name="get_ip_info"),
    path('get_deep_account/', DeepAccountSearchAPI.as_view(), name="get_deep_account"),
    path('get_wayback/', WaybackAPI.as_view(), name = "get_wayback"),
    path("get_ssl_info/", SSLInfoAPI.as_view(), name="get_ssl_info"),
    path("get_phone_info/", PhoneInfoAPI.as_view(), name="get_phone_info"),
    path('get_nrich/', NrichAPI.as_view(), name ="get_nrich"),
]