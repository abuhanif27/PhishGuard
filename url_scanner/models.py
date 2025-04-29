from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


class URLScan(models.Model):
    """Model for storing URL scan data"""
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    url = models.URLField(max_length=2000)
    scan_date = models.DateTimeField(default=timezone.now)
    is_phishing = models.BooleanField(null=True, blank=True)
    confidence_score = models.FloatField(null=True, blank=True)
    
    # Scan details
    domain_age_days = models.IntegerField(null=True, blank=True)
    uses_https = models.BooleanField(null=True, blank=True)
    contains_suspicious_words = models.BooleanField(null=True, blank=True)
    suspicious_words = models.TextField(null=True, blank=True)
    redirects_count = models.IntegerField(null=True, blank=True)
    has_known_phishing_patterns = models.BooleanField(null=True, blank=True)
    phishing_patterns = models.TextField(null=True, blank=True)
    ssl_valid = models.BooleanField(null=True, blank=True)
    domain_in_whitelist = models.BooleanField(null=True, blank=True)
    domain_in_blacklist = models.BooleanField(null=True, blank=True)
    
    def __str__(self):
        return f"{self.url} - {self.scan_date.strftime('%Y-%m-%d %H:%M')}"
    
    class Meta:
        ordering = ['-scan_date']
        verbose_name = 'URL Scan'
        verbose_name_plural = 'URL Scans'


class PhishingPattern(models.Model):
    """Model for storing known phishing patterns"""
    
    pattern_name = models.CharField(max_length=100)
    pattern_regex = models.CharField(max_length=500)
    description = models.TextField()
    severity = models.IntegerField(default=1, choices=(
        (1, 'Low'),
        (2, 'Medium'),
        (3, 'High'),
        (4, 'Critical'),
    ))
    created_date = models.DateTimeField(default=timezone.now)
    is_active = models.BooleanField(default=True)
    
    def __str__(self):
        return self.pattern_name
    
    class Meta:
        ordering = ['-severity', 'pattern_name']
        verbose_name = 'Phishing Pattern'
        verbose_name_plural = 'Phishing Patterns'
