from django.contrib import admin
from .models import UserProfile, PhishingDatabase
from django.utils.html import format_html


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'organization', 'job_title', 'date_joined', 'email_notifications', 'enable_two_factor')
    list_filter = ('email_notifications', 'enable_two_factor', 'date_joined')
    search_fields = ('user__username', 'user__email', 'organization', 'job_title')
    readonly_fields = ('user', 'date_joined')
    fieldsets = (
        ('User Information', {
            'fields': ('user', 'date_joined', 'organization', 'job_title', 'api_key')
        }),
        ('Notification Settings', {
            'fields': ('email_notifications', 'enable_two_factor', 'scan_history_days')
        }),
    )


@admin.register(PhishingDatabase)
class PhishingDatabaseAdmin(admin.ModelAdmin):
    list_display = ('name', 'url_display', 'is_active', 'last_updated', 'update_frequency_hours')
    list_filter = ('is_active', 'last_updated')
    search_fields = ('name', 'description')
    
    def url_display(self, obj):
        return format_html('<a href="{}" target="_blank">{}</a>', obj.url, obj.url)
    
    url_display.short_description = 'URL'
