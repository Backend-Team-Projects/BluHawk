from django.db import models
from django.contrib.auth.models import User

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=100, blank=True, null=True)
    phone = models.CharField(max_length=15, blank=True, null=True)
    secondary_email = models.EmailField(blank=True, null=True)
    # profile_picture = models.ImageField(upload_to='profile_pictures/', blank=True, null=True)

    def __str__(self):
        return self.user.username if self.user else "No User"

class UserSettings(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    dark_mode = models.BooleanField(default=True)
    email_notifications_enabled = models.BooleanField(default=True)
    phone_notifications_enabled = models.BooleanField(default=False)
    two_factor_auth_enabled = models.BooleanField(default=False)

    def __str__(self):
        return f"Settings for {self.user.username}" if self.user else "No User Settings"