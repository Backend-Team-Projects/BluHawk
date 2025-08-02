from django.db import models
import json
from django.db import models
from django.utils import timezone

class MitreAttackEntity(models.Model):
    id = models.CharField(primary_key=True, max_length=255)
    name = models.CharField(max_length=255)
    type = models.CharField(max_length=255)
    modified = models.DateTimeField()
    created = models.DateTimeField()
    json_data = models.JSONField()
    target = models.CharField(max_length=255)
    target_id = models.CharField(max_length=255)
    mitre_object_id = models.CharField(max_length=255, default="")
    
    def __str__(self):
        return f"{self.type}, {self.name}, {self.modified}, {self.modified}, {self.target}"

class CVE(models.Model):
    id = models.CharField(primary_key=True, max_length=255)
    type = models.CharField(max_length=255)
    name = models.CharField(max_length=255)
    modified = models.DateTimeField()
    created = models.DateTimeField()
    json_data = models.JSONField()
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.type}, {self.name}, {self.modified}, {self.modified}"

class CveNvd(models.Model):
    id = models.CharField(primary_key=True, max_length=255)
    type = models.CharField(max_length=255)
    name = models.CharField(max_length=255,)
    modified = models.DateTimeField()
    created = models.DateTimeField()
    json_data = models.JSONField()
    updated_at = models.DateTimeField(auto_now=True)

class CPE(models.Model):
    id = models.CharField(max_length=100, primary_key=True)
    type = models.CharField(max_length=50, default="CPE")
    name = models.CharField(max_length=255, db_index=True)
    created = models.DateTimeField(auto_now_add=True)
    vendor = models.CharField(max_length=100, db_index=True)
    product = models.CharField(max_length=100, db_index=True)
    cve_ids = models.ManyToManyField('dashboard.CveNvd', related_name='cpe_entries')


    

class Misp(models.Model):
    id = models.CharField(primary_key=True, max_length=255)
    type = models.CharField(max_length=255)
    name = models.CharField(max_length=255)
    source_type = models.CharField(max_length=255)
    json_data = models.JSONField()
    
    def __str__(self):
        return f"{self.type}, {self.id}, {self.json_data}"

class MitreEntityRelation(models.Model):
    id = models.CharField(primary_key=True, max_length=255)
    type = models.CharField(max_length=255)
    modified = models.DateTimeField()
    created = models.DateTimeField()
    json_data = models.JSONField()
    relationship_type = models.CharField(max_length=255)
    source_ref = models.CharField(max_length=255)
    target_ref = models.CharField(max_length=255)
    
    def __str__(self):
        return f"{self.type}, {self.relationship_type}, {self.source_ref}, {self.target_ref}"

class Subscribers(models.Model):
    email = models.EmailField()
    created = models.DateTimeField(auto_now_add=True)
    entity_id = models.CharField(max_length=255)
    entity_source = models.CharField(max_length=255)
    
    def __str__(self):
        return f"{self.email}, {self.created}"

class WapitiReports(models.Model):
    id = models.CharField(primary_key=True, max_length=255)
    json_data = models.JSONField()
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.id}, {self.json_data}"

class CompanyProfile(models.Model):
    domain = models.CharField( max_length=255)
    company_name = models.CharField(max_length=255, db_index=True, default = '')
    json_data = models.JSONField()
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.id}, {self.json_data}"

class OpenPorts(models.Model):
    id = models.CharField(primary_key = True, max_length=255)
    ports = models.JSONField()
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.id}, {self.ports}"

class Subdomains(models.Model):
    id = models.CharField(primary_key = True, max_length=255)
    subdomains = models.JSONField()
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.id}, {self.subdomains}"

class FullSubdomains(models.Model):
    id = models.CharField(primary_key = True, max_length=255)
    subdomains = models.JSONField()
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.id}, {self.subdomains}"

class ErrorLogs(models.Model):
    error = models.JSONField()
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.id}, {self.error}"



class FullScanReport(models.Model):
    STATUS_CHOICES = [
        ("processing", "Processing"),
        ("completed", "Completed"),
        ("error", "Error"),
    ]
    
    TYPE_CHOICES = [
        ("ip", "IP"),
        ("domain", "Domain"),
        ("url", "URL"),
        ("hash", "Hash"),
    ]

    id = models.CharField(primary_key=True, max_length=255)
    search_type = models.CharField(max_length=20, choices=TYPE_CHOICES)
    
    scan_data = models.JSONField(null=True, blank=True)  # ← Single field for all scan results

    scan_started_at = models.DateTimeField(default=timezone.now)
    scan_completed_at = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="processing")
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.id} ({self.search_type}) - {self.status}"
