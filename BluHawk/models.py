from django.db import models
from django.contrib.auth.models import User

class UserRequestLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    endpoint = models.CharField(max_length=255)
    count = models.IntegerField(default=0)
    last_request = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("user", "endpoint")

    def __str__(self):
        return f"{self.user.username} - {self.endpoint} - {self.count} requests"
