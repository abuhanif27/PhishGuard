from django.contrib import admin
from .models import EmailAnalysis, PhishingIndicator
from django.utils.html import format_html


@admin.register(EmailAnalysis)
class EmailAnalysisAdmin(admin.ModelAdmin):
    list_display = ('email_subject_display', 'email_sender', 'user', 'analysis_date', 'phishing_status', 'confidence_score')
    list_filter = ('is_phishing', 'analysis_date', 'has_suspicious_links', 'has_urgent_language', 'has_misspellings', 'has_suspicious_attachments')
    search_fields = ('email_subject', 'email_sender', 'email_body', 'user__username')
    readonly_fields = ('analysis_date', 'email_subject', 'email_sender', 'email_body_display', 'is_phishing', 'confidence_score',
                      'has_suspicious_links', 'suspicious_links', 'has_urgent_language', 'urgent_phrases',
                      'has_misspellings', 'misspelled_words', 'has_suspicious_attachments', 'suspicious_attachments',
                      'has_spoofed_sender', 'sender_in_blacklist', 'sender_in_whitelist')
    
    fieldsets = (
        ('Analysis Information', {
            'fields': ('user', 'analysis_date', 'email_sender')
        }),
        ('Email Content', {
            'fields': ('email_subject', 'email_body_display')
        }),
        ('Analysis Results', {
            'fields': ('is_phishing', 'confidence_score')
        }),
        ('Email Indicators', {
            'fields': ('has_suspicious_links', 'suspicious_links', 'has_urgent_language', 'urgent_phrases',
                      'has_misspellings', 'misspelled_words', 'has_suspicious_attachments', 'suspicious_attachments')
        }),
        ('Sender Analysis', {
            'fields': ('has_spoofed_sender', 'sender_in_blacklist', 'sender_in_whitelist')
        }),
    )
    
    def email_subject_display(self, obj):
        max_length = 50
        display_subject = obj.email_subject if len(obj.email_subject) <= max_length else obj.email_subject[:max_length] + '...'
        return display_subject
    
    def email_body_display(self, obj):
        return format_html('<div style="max-height: 300px; overflow-y: auto; padding: 10px; border: 1px solid #e5e7eb; border-radius: 0.375rem; background-color: #f9fafb;">{}</div>', obj.email_body.replace('\n', '<br>'))
    
    def phishing_status(self, obj):
        if obj.is_phishing is None:
            return format_html('<span style="color: #6b7280;">Unknown</span>')
        elif obj.is_phishing:
            return format_html('<span style="color: #ef4444; font-weight: bold;">Phishing</span>')
        else:
            return format_html('<span style="color: #10b981; font-weight: bold;">Safe</span>')
    
    email_subject_display.short_description = 'Subject'
    email_body_display.short_description = 'Email Body'
    phishing_status.short_description = 'Status'


@admin.register(PhishingIndicator)
class PhishingIndicatorAdmin(admin.ModelAdmin):
    list_display = ('indicator_name', 'indicator_type', 'severity_display', 'is_active', 'created_date')
    list_filter = ('indicator_type', 'severity', 'is_active', 'created_date')
    search_fields = ('indicator_name', 'pattern_value', 'description')
    
    def severity_display(self, obj):
        severity_colors = {
            1: '#6b7280',  # Gray for Low
            2: '#f59e0b',  # Amber for Medium
            3: '#ef4444',  # Red for High
            4: '#7f1d1d',  # Dark red for Critical
        }
        severity_labels = {
            1: 'Low',
            2: 'Medium',
            3: 'High',
            4: 'Critical',
        }
        color = severity_colors.get(obj.severity, '#6b7280')
        label = severity_labels.get(obj.severity, 'Unknown')
        return format_html('<span style="color: {}; font-weight: bold;">{}</span>', color, label)
    
    severity_display.short_description = 'Severity'
