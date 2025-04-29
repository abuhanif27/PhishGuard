from django.urls import path
from . import views

app_name = 'dashboard'

urlpatterns = [
    path('', views.dashboard_home, name='home'),
    path('profile/', views.user_profile, name='profile'),
    path('history/', views.scan_history, name='history'),
] 