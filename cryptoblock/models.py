from django.db import models

from django.contrib.auth.models import User

class FileUploadHistory(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    filename = models.CharField(max_length=255)
    filehash = models.CharField(max_length=255)
    json_data = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # class Meta:
    #     unique_together = ("user", "endpoint")

    def __str__(self):
        return f"{self.user.username} - {self.endpoint} - {self.count} requests"
