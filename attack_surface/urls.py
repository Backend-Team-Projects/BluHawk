# attack_surface/urls.py
from django.urls import path
from .views import AttackSurface, AttackSurfaceAPI, CveDetailsAPI

urlpatterns = [
    path('search/', AttackSurface.as_view(), name='AttackSurface'),
    path('scan/', AttackSurfaceAPI.as_view(), name='attack-surface-scan'),
    path('cve-details/', CveDetailsAPI.as_view(), name='cve_details')
]