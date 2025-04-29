from django.urls import path
from . import views

app_name = 'email_analyzer'

urlpatterns = [
    path('', views.analyze_email, name='analyze'),
    path('results/<int:analysis_id>/', views.analysis_results, name='results'),
    path('api/analyze/', views.api_analyze_email, name='api_analyze'),
] 