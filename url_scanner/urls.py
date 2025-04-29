from django.urls import path
from . import views

app_name = 'url_scanner'

urlpatterns = [
    path('', views.scan_url, name='scan'),
    path('results/<int:scan_id>/', views.scan_results, name='results'),
    path('api/scan/', views.api_scan_url, name='api_scan'),
] 