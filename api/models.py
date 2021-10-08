from django.db import models
from django.contrib.auth.models import User


# Create your models here.

class Garages(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100, blank=False)
    user = models.ForeignKey(User, related_name='user', null=False, on_delete=models.CASCADE)
    location = models.DecimalField(max_digits=9, decimal_places=6)
    garage_detail = models.TextField(blank=True)
    additional_services = models.TextField(blank=True)
    phone = models.CharField(max_length=30, blank=True, default='xxxx')
    timing = models.CharField(max_length=500, blank=False)
    image = models.ImageField(null=True, blank=True, upload_to='images/')
