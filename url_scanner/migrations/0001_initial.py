# Generated by Django 5.1.7 on 2025-03-12 21:27

import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='PhishingPattern',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('pattern_name', models.CharField(max_length=100)),
                ('pattern_regex', models.CharField(max_length=500)),
                ('description', models.TextField()),
                ('severity', models.IntegerField(choices=[(1, 'Low'), (2, 'Medium'), (3, 'High'), (4, 'Critical')], default=1)),
                ('created_date', models.DateTimeField(default=django.utils.timezone.now)),
                ('is_active', models.BooleanField(default=True)),
            ],
            options={
                'verbose_name': 'Phishing Pattern',
                'verbose_name_plural': 'Phishing Patterns',
                'ordering': ['-severity', 'pattern_name'],
            },
        ),
        migrations.CreateModel(
            name='URLScan',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('url', models.URLField(max_length=2000)),
                ('scan_date', models.DateTimeField(default=django.utils.timezone.now)),
                ('is_phishing', models.BooleanField(blank=True, null=True)),
                ('confidence_score', models.FloatField(blank=True, null=True)),
                ('domain_age_days', models.IntegerField(blank=True, null=True)),
                ('uses_https', models.BooleanField(blank=True, null=True)),
                ('contains_suspicious_words', models.BooleanField(blank=True, null=True)),
                ('suspicious_words', models.TextField(blank=True, null=True)),
                ('redirects_count', models.IntegerField(blank=True, null=True)),
                ('has_known_phishing_patterns', models.BooleanField(blank=True, null=True)),
                ('phishing_patterns', models.TextField(blank=True, null=True)),
                ('ssl_valid', models.BooleanField(blank=True, null=True)),
                ('domain_in_whitelist', models.BooleanField(blank=True, null=True)),
                ('domain_in_blacklist', models.BooleanField(blank=True, null=True)),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'URL Scan',
                'verbose_name_plural': 'URL Scans',
                'ordering': ['-scan_date'],
            },
        ),
    ]
