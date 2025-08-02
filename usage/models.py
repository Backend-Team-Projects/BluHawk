from django.db import models
from django.contrib.auth.models import User


class RequestLogs(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    api_name = models.CharField(max_length=255)
    group =  models.CharField(max_length=255)
    status_code = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)