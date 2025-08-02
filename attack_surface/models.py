from django.db import models
from django.db.models import JSONField
from django.utils.timezone import now

class AttackSurfaceScan(models.Model):
    domain = models.CharField(max_length=255)
    scan_type = models.CharField(max_length=50, default='complete')
    status = models.CharField(max_length=20, default='pending')
    scanned_at = models.DateTimeField(default=now)
    jsondata = JSONField(default=dict)
    progress = JSONField(default=list)  # Store task progress as a list of dictionaries

    class Meta:
        unique_together = ('domain', 'scan_type')
        db_table = 'attack_surface_scan'

    def __str__(self):
        return f"{self.domain} - {self.scan_type} - {self.status}"

class SSL(models.Model):
    domain = models.CharField(max_length=255)
    scan_type = models.CharField(max_length=50)
    status = models.CharField(max_length=20)
    scanned_at = models.DateTimeField(default=now)
    jsondata = JSONField(default=dict)

    class Meta:
        unique_together = ('domain', 'scan_type')
        db_table = 'ssl'

    def __str__(self):
        return f"SSL {self.domain} - {self.scan_type} - {self.status}"

class SSLRecord(models.Model):
    target = models.CharField(max_length=255)
    status = models.CharField(max_length=20)
    scanned_at = models.DateTimeField(default=now)
    json_data = JSONField(default=dict)
    
    class Meta:
        db_table = 'ssl_record'

    def __str__(self):
        return f"SSLRecord {self.target} - {self.status}"

class TechnologyDescription(models.Model):
    technology = models.CharField(max_length=255, unique=True, db_index=True)
    description = models.JSONField(default=dict)
    created_at = models.DateTimeField(default=now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=['technology'])
        ]
        db_table = 'technology_description'

    def __str__(self):
        return f"{self.technology} - Updated: {self.updated_at}"

class VulnerabilityDescription(models.Model):
    vulnerability = models.CharField(max_length=255, unique=True, db_index=True)
    description = models.JSONField(default=dict)
    created_at = models.DateTimeField(default=now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=['vulnerability'])
        ]
        db_table = 'vulnerability_description'

    def __str__(self):
        return f"{self.vulnerability} - Updated: {self.updated_at}"

class PortDescription(models.Model):
    port = models.CharField(max_length=5, unique=True, db_index=True)  # Port numbers as strings (e.g., "80", "443")
    description = models.JSONField(default=dict)
    created_at = models.DateTimeField(default=now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=['port'])
        ]
        db_table = 'port_description'

    def __str__(self):
        return f"Port {self.port} - Updated: {self.updated_at}"

# from django.db import models
# import json

# class AttackSurfaceScanResults(models.Model):
#     id = models.CharField(primary_key=True, max_length=255)
#     domain = models.CharField(max_length=255, db_index=True)
#     scan_status = models.CharField(max_length=50, default='inactive')
#     created_at = models.DateTimeField()
#     json_data = models.JSONField()
    
#     def __str__(self):
#         return f"{self.id}, {self.scan_status}, {self.created_at}"


class Notification(models.Model):
    email = models.CharField(max_length=255, db_index=True)
    heading = models.CharField(max_length=255)
    message = models.TextField()


    actionable = models.BooleanField(default=False, db_index=True)

    json_data = models.JSONField()

    type = models.CharField(max_length=50, default='info', db_index=True)

    created_at = models.DateTimeField(auto_now_add=True)

    organization_id = models.CharField(max_length=255, null=True, blank=True, db_index=True)

    seen = models.BooleanField(default=False, db_index=True)

    action_status = models.CharField(max_length=50, default='pending')

    def __str__(self):
        return f"{self.id}, {self.heading}, {self.type}, {self.created_at}"
    
