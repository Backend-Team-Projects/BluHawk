from django.db import models
import json

class DeepAccountSearch(models.Model):
    id = models.CharField(primary_key=True, max_length=255)
    json_data = models.JSONField()
    created = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
class PhoneNumberInfo(models.Model):
    id = models.CharField(primary_key=True, max_length=255)
    json_data = models.JSONField()
    created = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class SSLInfo(models.Model):
    id = models.CharField(primary_key=True, max_length=255)
    json_data = models.JSONField()
    created = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class DomainWayback(models.Model):
    id = models.CharField(primary_key=True, max_length=255)
    json_data = models.JSONField()
    created = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class UsernameSearch(models.Model):
    id = models.CharField(primary_key=True, max_length=255)
    json_data = models.JSONField()
    created = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class WhoIS(models.Model):
    id = models.CharField(primary_key=True, max_length=255)
    json_data = models.JSONField()
    created = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class IPInfo(models.Model):
    id = models.CharField(primary_key=True, max_length=255)
    json_data = models.JSONField()
    created = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class Nrich(models.Model):
    id = models.CharField(primary_key=True, max_length=255)
    json_data = models.JSONField()
    created = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)