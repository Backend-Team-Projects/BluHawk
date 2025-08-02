
from django.contrib import admin
from django.urls import path
from user_settings.views import *

urlpatterns = [
    # 2fa
    path('user_settings/', UserSettingsView.as_view(), name='user_settings_views'),
] 