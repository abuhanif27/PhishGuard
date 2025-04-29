from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


class EmailAnalysis(models.Model):
    """Model for storing email analysis data"""
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    email_subject = models.CharField(max_length=500)
    email_body = models.TextField()
    email_sender = models.EmailField(max_length=255)
    analysis_date = models.DateTimeField(default=timezone.now)
    is_phishing = models.BooleanField(null=True, blank=True)
    confidence_score = models.FloatField(null=True, blank=True)
    
    # Analysis details
    has_suspicious_links = models.BooleanField(null=True, blank=True)
    suspicious_links = models.TextField(null=True, blank=True)
    has_urgent_language = models.BooleanField(null=True, blank=True)
    urgent_phrases = models.TextField(null=True, blank=True)
    has_misspellings = models.BooleanField(null=True, blank=True)
    misspelled_words = models.TextField(null=True, blank=True)
    has_suspicious_attachments = models.BooleanField(null=True, blank=True)
    suspicious_attachments = models.TextField(null=True, blank=True)
    has_spoofed_sender = models.BooleanField(null=True, blank=True)
    sender_in_blacklist = models.BooleanField(null=True, blank=True)
    sender_in_whitelist = models.BooleanField(null=True, blank=True)
    
    def __str__(self):
        return f"{self.email_subject} - {self.analysis_date.strftime('%Y-%m-%d %H:%M')}"
    
    class Meta:
        ordering = ['-analysis_date']
        verbose_name = 'Email Analysis'
        verbose_name_plural = 'Email Analyses'


class PhishingIndicator(models.Model):
    """Model for storing known phishing indicators in emails"""
    
    indicator_name = models.CharField(max_length=100)
    indicator_type = models.CharField(max_length=50, choices=(
        ('phrase', 'Urgent/Suspicious Phrase'),
        ('pattern', 'Text Pattern'),
        ('domain', 'Suspicious Domain'),
        ('attachment', 'Suspicious Attachment Type'),
    ))
    pattern_value = models.CharField(max_length=500)
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
        return f"{self.indicator_name} ({self.get_indicator_type_display()})"
    
    class Meta:
        ordering = ['-severity', 'indicator_name']
        verbose_name = 'Phishing Indicator'
        verbose_name_plural = 'Phishing Indicators'
