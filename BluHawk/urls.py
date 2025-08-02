# BluHawk/urls.py
from django.contrib import admin
from django.urls import path, include


urlpatterns = [
    path('admin/', admin.site.urls),
    path('auth/', include('session_management.urls')),
    path('dashboard/', include('dashboard.urls')),
    path('wildcard_intel/', include('clatscope.urls')),
    path('usage/', include('usage.urls')),
    path('crypto/', include('cryptoblock.urls') ),
    path('vtreport/', include('vtreport.urls')),
    path("graphs/", include("vtgraph.urls")),
    path('api/attack-surface/', include('attack_surface.urls')),

    path('profile/', include('user_settings.urls')),


]
