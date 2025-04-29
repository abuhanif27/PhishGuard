from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import login, authenticate
from url_scanner.models import URLScan
from email_analyzer.models import EmailAnalysis
from .models import UserProfile


def dashboard_home(request):
    """Home page view for the dashboard"""
    
    # Get recent scans for authenticated users
    recent_url_scans = []
    recent_email_analyses = []
    
    if request.user.is_authenticated:
        recent_url_scans = URLScan.objects.filter(user=request.user).order_by('-scan_date')[:5]
        recent_email_analyses = EmailAnalysis.objects.filter(user=request.user).order_by('-analysis_date')[:5]
    
    context = {
        'recent_url_scans': recent_url_scans,
        'recent_email_analyses': recent_email_analyses,
    }
    
    return render(request, 'dashboard/home.html', context)


@login_required
def user_profile(request):
    """View for user profile"""
    
    try:
        profile = request.user.profile
    except UserProfile.DoesNotExist:
        profile = UserProfile.objects.create(user=request.user)
    
    if request.method == 'POST':
        # Update profile settings
        profile.email_notifications = 'email_notifications' in request.POST
        profile.enable_two_factor = 'enable_two_factor' in request.POST
        profile.scan_history_days = int(request.POST.get('scan_history_days', 30))
        profile.save()
        messages.success(request, 'Profile settings updated successfully!')
        return redirect('dashboard:profile')
    
    # Get statistics for the template
    url_scans = URLScan.objects.filter(user=request.user)
    email_analyses = EmailAnalysis.objects.filter(user=request.user)
    
    total_scans = url_scans.count() + email_analyses.count()
    threats_detected = url_scans.filter(is_phishing=True).count() + email_analyses.filter(is_phishing=True).count()
    
    # Get the most recent scan date
    last_scan_date = None
    latest_url_scan = url_scans.order_by('-scan_date').first()
    latest_email_analysis = email_analyses.order_by('-analysis_date').first()
    
    if latest_url_scan and latest_email_analysis:
        if latest_url_scan.scan_date > latest_email_analysis.analysis_date:
            last_scan_date = latest_url_scan.scan_date
        else:
            last_scan_date = latest_email_analysis.analysis_date
    elif latest_url_scan:
        last_scan_date = latest_url_scan.scan_date
    elif latest_email_analysis:
        last_scan_date = latest_email_analysis.analysis_date
    
    if last_scan_date:
        last_scan_date = last_scan_date.strftime('%B %d, %Y')
    
    context = {
        'profile': profile,
        'total_scans': total_scans,
        'threats_detected': threats_detected,
        'last_scan_date': last_scan_date,
    }
    
    return render(request, 'dashboard/profile.html', context)


@login_required
def scan_history(request):
    """View for displaying scan history"""
    
    url_scans = URLScan.objects.filter(user=request.user).order_by('-scan_date')
    email_analyses = EmailAnalysis.objects.filter(user=request.user).order_by('-analysis_date')
    
    context = {
        'url_scans': url_scans,
        'email_analyses': email_analyses,
    }
    
    return render(request, 'dashboard/history.html', context)


def register(request):
    """View for user registration"""
    
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            # Create user profile
            UserProfile.objects.create(user=user)
            # Log the user in
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password1')
            user = authenticate(username=username, password=password)
            login(request, user)
            messages.success(request, f'Account created for {username}!')
            return redirect('dashboard:home')
    else:
        form = UserCreationForm()
    
    return render(request, 'registration/register.html', {'form': form})
