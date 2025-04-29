from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


class UserProfile(models.Model):
    """Extended user profile model"""
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    organization = models.CharField(max_length=100, blank=True, null=True)
    job_title = models.CharField(max_length=100, blank=True, null=True)
    api_key = models.CharField(max_length=64, blank=True, null=True)
    date_joined = models.DateTimeField(default=timezone.now)
    
    # Notification settings
    email_notifications = models.BooleanField(default=True)
    enable_two_factor = models.BooleanField(default=False)
    scan_history_days = models.IntegerField(default=30)
    
    def __str__(self):
        return f"{self.user.username}'s Profile"
    
    class Meta:
        verbose_name = 'User Profile'
        verbose_name_plural = 'User Profiles'


class PhishingDatabase(models.Model):
    """Model for external phishing databases"""
    
    name = models.CharField(max_length=100)
    url = models.URLField(max_length=500)
    api_key = models.CharField(max_length=100, blank=True, null=True)
    description = models.TextField()
    is_active = models.BooleanField(default=True)
    last_updated = models.DateTimeField(default=timezone.now)
    update_frequency_hours = models.IntegerField(default=24)
    
    def __str__(self):
        return self.name
    
    class Meta:
        verbose_name = 'Phishing Database'
        verbose_name_plural = 'Phishing Databases'
