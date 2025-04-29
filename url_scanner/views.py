from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib import messages
import json
import re
import requests
from bs4 import BeautifulSoup
from .models import URLScan, PhishingPattern
from django.utils import timezone


def scan_url(request):
    """View for scanning a URL"""
    
    if request.method == 'POST':
        url = request.POST.get('url', '').strip()
        
        if not url:
            messages.error(request, 'Please enter a URL to scan.')
            return redirect('url_scanner:scan')
        
        # Add http:// prefix if missing
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # Create a new scan record
        scan = URLScan(
            url=url,
            user=request.user if request.user.is_authenticated else None
        )
        
        # Perform the scan
        perform_url_scan(scan)
        scan.save()
        
        return redirect('url_scanner:results', scan_id=scan.id)
    
    return render(request, 'url_scanner/scan.html')


def scan_results(request, scan_id):
    """View for displaying scan results"""
    
    scan = get_object_or_404(URLScan, id=scan_id)
    
    # Check if the user has permission to view this scan
    if scan.user and request.user != scan.user and not request.user.is_staff:
        messages.error(request, 'You do not have permission to view this scan.')
        return redirect('url_scanner:scan')
    
    context = {
        'scan': scan,
    }
    
    return render(request, 'url_scanner/results.html', context)


@csrf_exempt
def api_scan_url(request):
    """API endpoint for scanning a URL"""
    
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST method is allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        url = data.get('url', '').strip()
        
        if not url:
            return JsonResponse({'error': 'URL is required'}, status=400)
        
        # Add http:// prefix if missing
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # Create a new scan record
        scan = URLScan(url=url)
        
        # Perform the scan
        perform_url_scan(scan)
        scan.save()
        
        # Return the scan results
        return JsonResponse({
            'scan_id': scan.id,
            'is_phishing': scan.is_phishing,
            'confidence_score': scan.confidence_score,
            'details': {
                'uses_https': scan.uses_https,
                'ssl_valid': scan.ssl_valid,
                'redirects_count': scan.redirects_count,
                'contains_suspicious_words': scan.contains_suspicious_words,
                'suspicious_words': scan.suspicious_words.split(',') if scan.suspicious_words else [],
                'has_known_phishing_patterns': scan.has_known_phishing_patterns,
                'phishing_patterns': scan.phishing_patterns.split(',') if scan.phishing_patterns else [],
                'domain_in_blacklist': scan.domain_in_blacklist,
                'domain_in_whitelist': scan.domain_in_whitelist,
            }
        })
    
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


def perform_url_scan(scan):
    """Perform the URL scanning with error handling"""
    
    # Initialize scan details
    scan.uses_https = scan.url.startswith('https://')
    scan.redirects_count = 0
    scan.contains_suspicious_words = False
    scan.has_known_phishing_patterns = False
    
    try:
        # Fetch URL content with timeout and track redirects
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            response = requests.get(scan.url, timeout=10, allow_redirects=True, headers=headers)
            scan.redirects_count = len(response.history)
            final_url = response.url
            
            # Check SSL validity
            scan.ssl_valid = response.url.startswith('https://')
        except Exception as e:
            # If request fails, set defaults and continue with partial analysis
            scan.ssl_valid = False
            final_url = scan.url
            print(f"URL request error: {str(e)}")
        
        # Extract domain
        domain_match = re.search(r'https?://([^/]+)', final_url)
        domain = domain_match.group(1) if domain_match else ''
        
        # Check for suspicious words in URL - expanded list
        suspicious_words = [
            'login', 'secure', 'account', 'banking', 'verify', 'update', 'confirm',
            'signin', 'password', 'credential', 'security', 'authentic', 'official',
            'wallet', 'recover', 'reset', 'alert', 'validate', 'support', 'verify',
            'access', 'authorize', 'limited', 'suspended', 'unusual', 'activity',
            'paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook', 'verification'
        ]
        found_suspicious_words = []
        
        # Look for suspicious words in both domain and full URL
        for word in suspicious_words:
            if word.lower() in final_url.lower():
                found_suspicious_words.append(word)
        
        # Special check for deceptive domains that use numbers instead of letters
        common_replacements = {
            'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 'l': '1'
        }
        
        legitimate_domains = ['paypal.com', 'gmail.com', 'amazon.com', 'apple.com', 
                             'microsoft.com', 'google.com', 'facebook.com', 'instagram.com']
        
        for legit_domain in legitimate_domains:
            base_domain = legit_domain.split('.')[0]
            
            # Check for domains with substituted characters
            for char, replacement in common_replacements.items():
                modified_domain = base_domain.replace(char, replacement)
                if modified_domain != base_domain and modified_domain in domain:
                    found_suspicious_words.append(f"deceptive-{base_domain}")
                    break
        
        scan.contains_suspicious_words = len(found_suspicious_words) > 0
        scan.suspicious_words = ','.join(found_suspicious_words) if found_suspicious_words else None
        
        # Check for known phishing patterns
        patterns = PhishingPattern.objects.filter(is_active=True)
        found_patterns = []
        
        # Try to analyze page content if available
        try:
            if 'response' in locals() and hasattr(response, 'text'):
                soup = BeautifulSoup(response.text, 'html.parser')
                page_text = soup.get_text()
                
                # Check for login forms with suspicious attributes
                login_forms = soup.find_all('form')
                for form in login_forms:
                    action = form.get('action', '')
                    if ('login' in action.lower() or 'signin' in action.lower()):
                        if not scan.ssl_valid:
                            found_patterns.append('Insecure login form')
                        
                        # Look for suspicious form targets (external domains)
                        if action.startswith(('http://', 'https://')) and domain not in action:
                            found_patterns.append('Form submits to external domain')
                
                # Look for password fields on non-HTTPS pages
                if not scan.ssl_valid and soup.find('input', {'type': 'password'}):
                    found_patterns.append('Password field on non-HTTPS page')
                
                # Look for hidden fields with suspicious names
                hidden_fields = soup.find_all('input', {'type': 'hidden'})
                for field in hidden_fields:
                    field_name = field.get('name', '').lower()
                    if any(word in field_name for word in ['redirect', 'return', 'callback']):
                        field_value = field.get('value', '')
                        if field_value.startswith(('http://', 'https://')) and domain not in field_value:
                            found_patterns.append('Hidden redirect to external domain')
                
                # Check for excessive external resources
                external_resources = []
                for tag in soup.find_all(['script', 'img', 'link', 'iframe']):
                    src = tag.get('src') or tag.get('href') or ''
                    if src.startswith(('http://', 'https://')) and domain not in src:
                        external_resources.append(src)
                
                if len(external_resources) > 15:  # Arbitrary threshold
                    found_patterns.append('Excessive external resources')
                
                # Check for obfuscated JavaScript
                scripts = soup.find_all('script')
                for script in scripts:
                    script_text = script.string if script.string else ''
                    if script_text and ('eval(' in script_text or 'document.write(unescape(' in script_text):
                        found_patterns.append('Obfuscated JavaScript')
                        break
                
                # Check for suspicious keywords in the page content
                phishing_keywords = [
                    'verify your account', 'confirm your details', 'update your information',
                    'unusual activity', 'suspicious login attempt', 'limited access',
                    'account suspended', 'security measure', 'unauthorized access'
                ]
                
                for keyword in phishing_keywords:
                    if keyword.lower() in page_text.lower():
                        found_patterns.append(f"Suspicious content: {keyword}")
                        break
        except Exception as e:
            print(f"Content parsing error: {str(e)}")
        
        scan.has_known_phishing_patterns = len(found_patterns) > 0
        scan.phishing_patterns = ','.join(found_patterns) if found_patterns else None
        
        # Calculate phishing confidence score with improved weighting
        score = 0
        
        # Base indicators
        if not scan.uses_https:
            score += 0.2
        
        if scan.redirects_count > 2:
            score += 0.1 * min(scan.redirects_count, 5)
        
        # Suspicious words in URL
        if scan.contains_suspicious_words:
            word_count = len(found_suspicious_words)
            # Words like "deceptive-paypal" should count more
            deceptive_count = sum(1 for word in found_suspicious_words if word.startswith('deceptive-'))
            regular_count = word_count - deceptive_count
            
            score += 0.1 * regular_count + 0.3 * deceptive_count
        
        # Phishing patterns are strong indicators
        if scan.has_known_phishing_patterns:
            # Different patterns have different weights
            for pattern in found_patterns:
                if pattern == 'Password field on non-HTTPS page':
                    score += 0.3
                elif pattern.startswith('Suspicious content:'):
                    score += 0.15
                elif pattern == 'Form submits to external domain' or pattern == 'Hidden redirect to external domain':
                    score += 0.4
                elif pattern == 'Obfuscated JavaScript':
                    score += 0.25
                else:
                    score += 0.2
        
        # Domain characteristics
        if domain and ('.' in domain):
            domain_parts = domain.split('.')
            
            # Suspicious TLDs
            suspicious_tlds = ['.tk', '.top', '.xyz', '.online', '.info', '.club', '.ml', '.ga']
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                score += 0.1
            
            # Very short or very long domains can be suspicious
            if len(domain_parts[0]) < 3 or len(domain_parts[0]) > 20:
                score += 0.05
            
            # Domains with excessive hyphens
            if domain_parts[0].count('-') > 2:
                score += 0.1
            
            # Domains with excessive numbers
            if sum(c.isdigit() for c in domain_parts[0]) > 3:
                score += 0.1
        
        # Determine if the URL is likely a phishing site
        scan.confidence_score = min(score, 1.0)
        scan.is_phishing = scan.confidence_score > 0.5
        
    except Exception as e:
        print(f"URL scan error: {str(e)}")
        # If there's an error, mark as potentially suspicious
        scan.is_phishing = None
        scan.confidence_score = None
