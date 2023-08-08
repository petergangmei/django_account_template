from django.db import models
from django.contrib.auth.models import User


class Profile(models.Model):
    user = models.ForeignKey(User,on_delete=models.CASCADE)

    modified_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.user

class PasswordReset(models.Model):
    user = models.ForeignKey(User,on_delete=models.CASCADE)
    otp = models.IntegerField(default=0)
    valid_til = models.DateTimeField()
    password_updated = models.BooleanField(default=False)
    password = models.CharField(max_length=100)
    token = models.CharField(max_length=250)


    modified_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.user.username