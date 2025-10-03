from django.db import models
from django.contrib.auth.models import User
from datetime import timedelta
from django.utils.timezone import now, make_aware, timezone
from django.conf import settings

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    reset_token = models.CharField(max_length=255, null=True, blank=True)
    reset_token_created_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.user.username

    def is_reset_token_valid(self):
        if self.reset_token and self.reset_token_created_at:
            return now() <= self.reset_token_created_at + timedelta(hours=24)
        return False

class Verification(models.Model):
    email = models.CharField(max_length=255, null = False, blank=False)
    verification_key = models.CharField(max_length=255, null = False, blank=False)
    updated_at = models.DateTimeField(auto_now=True)

class Organization(models.Model):
    id = models.CharField(max_length=255, primary_key=True) 
    name = models.CharField(max_length=255, null = False, blank=False)
    address = models.CharField(max_length=255, null = False, blank=False)
    email = models.CharField(max_length=255, null = False, blank=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    country = models.CharField(max_length=255, null = False, blank=False)
    is_active = models.BooleanField(default=True)
    logo_url = models.CharField(max_length=255, null = True, blank=True)

    def __str__(self):
        return f"Organization: {self.name}"

class OrganizationManagement(models.Model):
    id = models.AutoField(primary_key=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    role = models.CharField(max_length=50, default='admin')

    def __str__(self):
        return f"Organization: {self.organization.name} - User: {self.user.username}"
    
class OrganizationInvitation(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('accepted', 'Accepted'),
        ('rejected', 'Rejected'),
    ]

    id = models.AutoField(primary_key=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    email = models.CharField(max_length=255)
    verification_code = models.CharField(max_length=255)
    role = models.CharField(max_length=50, default='viewer')
    updated_at = models.DateTimeField(auto_now=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending', db_index=True)
    invited_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL,related_name="sent_invitations")

    def __str__(self):
        return f"Organization Invitation: {self.organization.name} - Email: {self.email} - Role: {self.role} - Status: {self.status}"

def get_invitation_expiry(self):
        return timezone.now() + timedelta(days=7)

class Scanlog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    scan_name = models.CharField(max_length=255)
    group = models.CharField(max_length=50)
    status_code = models.IntegerField()
    organization = models.ForeignKey(Organization, on_delete=models.SET_NULL, null=True, blank=True)
    role = models.CharField(max_length=50, default='none')
    timestamp = models.DateTimeField(auto_now_add=True)
    json_data = models.JSONField(null=True, blank=True)
    compliance_mappings = models.JSONField(
        null=True,
        blank=True,
        default=list,
        help_text="List of compliance controls (e.g., PCI-DSS 8.2.3, ISO27001 A.12.4.1)"
    )

    def __str__(self):
        return f"{self.user.email} - {self.timestamp}"
