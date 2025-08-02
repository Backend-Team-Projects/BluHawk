from django.shortcuts import render

# Create your views here.
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from rest_framework.permissions import IsAuthenticated
from django.utils.timezone import now
from django.conf import settings
from BluHawk.utils import *
from BluHawk.models import *
from user_settings.models import UserProfile, UserSettings

class UserSettingsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        user_profile = UserProfile.objects.filter(user=user).first()
        user_settings = UserSettings.objects.filter(user=user).first()

        if not user_profile:
            UserProfile.objects.create(user=user, name=user.username)
            user_profile = UserProfile.objects.get(user=user)
        
        if not user_settings:
            UserSettings.objects.create(user=user)
            user_settings = UserSettings.objects.get(user=user)

        data = {
            "name": user_profile.name,
            "phone": user_profile.phone,
            "secondary_email": user_profile.secondary_email,
            "dark_mode": user_settings.dark_mode,
            "email_notifications_enabled": user_settings.email_notifications_enabled,
            "phone_notifications_enabled": user_settings.phone_notifications_enabled,
            "two_factor_auth_enabled": user_settings.two_factor_auth_enabled,
        }
        # print(data)
        # return Response(data, status=status.HTTP_200_OK)

    def post(self, request):
        user = request.user
        user_profile = UserProfile.objects.filter(user=user).first()
        user_settings = UserSettings.objects.filter(user=user).first()

        if not user_profile:
            UserProfile.objects.create(user=user, name=user.username)
            user_profile = UserProfile.objects.get(user=user)
        
        if not user_settings:
            UserSettings.objects.create(user=user)
            user_settings = UserSettings.objects.get(user=user)


        data = request.data

        # Update UserProfile fields
        user_profile.name = data.get("name", user_profile.name)
        user_profile.phone = data.get("phone", user_profile.phone)
        user_profile.secondary_email = data.get("secondary_email", user_profile.secondary_email)
        user_profile.save()

        # Update UserSettings fields
        user_settings.dark_mode = data.get("dark_mode", user_settings.dark_mode)
        user_settings.email_notifications_enabled = data.get("email_notifications_enabled", user_settings.email_notifications_enabled)
        user_settings.phone_notifications_enabled = data.get("phone_notifications_enabled", user_settings.phone_notifications_enabled)
        user_settings.two_factor_auth_enabled = data.get("two_factor_auth_enabled", user_settings.two_factor_auth_enabled)
        user_settings.save()

        return Response({"message": "Settings updated successfully."}, status=status.HTTP_200_OK)

    def delete(self, request):
        user = request.user
        user_profile = UserProfile.objects.filter(user=user).first()
        user_settings = UserSettings.objects.filter(user=user).first()

        if not user_profile:
            UserProfile.objects.create(user=user, name=user.username)
            user_profile = UserProfile.objects.get(user=user)
        
        if not user_settings:
            UserSettings.objects.create(user=user)
            user_settings = UserSettings.objects.get(user=user)

        user_profile.delete()
        user_settings.delete()

        return Response({"message": "User profile and settings deleted successfully."}, status=status.HTTP_204_NO_CONTENT)