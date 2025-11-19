from django.db import models
from django.contrib.auth.models import User
from session_management.models import Organization

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=100, blank=True, null=True)
    phone = models.CharField(max_length=15, blank=True, null=True)
    secondary_email = models.EmailField(blank=True, null=True)
    active_organization = models.ForeignKey(
        "session_management.Organization",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="active_users"
    )
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
    


from django.db.models.signals import post_save
from django.dispatch import receiver
from session_management.models import Profile

@receiver(post_save, sender=User)
def create_all_user_profiles(sender, instance, created, **kwargs):
    if created:

        # Main user profile
        UserProfile.objects.get_or_create(user=instance)

        # Settings profile
        UserSettings.objects.get_or_create(user=instance)

        # Password-reset profile (your Profile model)
        Profile.objects.get_or_create(user=instance)