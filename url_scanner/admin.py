from django.contrib import admin
from .models import URLScan, PhishingPattern
from django.utils.html import format_html


@admin.register(URLScan)
class URLScanAdmin(admin.ModelAdmin):
    list_display = ('url_display', 'user', 'scan_date', 'phishing_status', 'confidence_score')
    list_filter = ('is_phishing', 'scan_date', 'uses_https', 'contains_suspicious_words', 'has_known_phishing_patterns')
    search_fields = ('url', 'user__username')
    readonly_fields = ('scan_date', 'url', 'is_phishing', 'confidence_score', 'uses_https', 'domain_age_days', 
                     'contains_suspicious_words', 'suspicious_words', 'redirects_count', 'has_known_phishing_patterns',
                     'phishing_patterns', 'ssl_valid', 'domain_in_whitelist', 'domain_in_blacklist')
    
    fieldsets = (
        ('Scan Information', {
            'fields': ('user', 'url', 'scan_date')
        }),
        ('Analysis Results', {
            'fields': ('is_phishing', 'confidence_score')
        }),
        ('URL Details', {
            'fields': ('uses_https', 'ssl_valid', 'domain_age_days', 'redirects_count')
        }),
        ('Suspicious Indicators', {
            'fields': ('contains_suspicious_words', 'suspicious_words', 'has_known_phishing_patterns', 
                      'phishing_patterns', 'domain_in_whitelist', 'domain_in_blacklist')
        }),
    )
    
    def url_display(self, obj):
        max_length = 50
        display_url = obj.url if len(obj.url) <= max_length else obj.url[:max_length] + '...'
        return format_html('<a href="{}" target="_blank">{}</a>', obj.url, display_url)
    
    def phishing_status(self, obj):
        if obj.is_phishing is None:
            return format_html('<span style="color: #6b7280;">Unknown</span>')
        elif obj.is_phishing:
            return format_html('<span style="color: #ef4444; font-weight: bold;">Phishing</span>')
        else:
            return format_html('<span style="color: #10b981; font-weight: bold;">Safe</span>')
    
    url_display.short_description = 'URL'
    phishing_status.short_description = 'Status'


@admin.register(PhishingPattern)
class PhishingPatternAdmin(admin.ModelAdmin):
    list_display = ('pattern_name', 'severity_display', 'is_active', 'created_date')
    list_filter = ('severity', 'is_active', 'created_date')
    search_fields = ('pattern_name', 'pattern_regex', 'description')
    
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
