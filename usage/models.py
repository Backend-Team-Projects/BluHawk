from django.db import models
from django.contrib.auth.models import User


class RequestLogs(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    api_name = models.CharField(max_length=255)
    group =  models.CharField(max_length=255)
    status_code = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
    compliance_metadata = models.JSONField(default=dict, blank=True, null=True)
    
    def __str__(self):
        return f"{self.user.username} - {self.api_name} - {self.status_code}"