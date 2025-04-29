from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib import messages
import json
import re
import nltk
from nltk.tokenize import word_tokenize
from bs4 import BeautifulSoup
from .models import EmailAnalysis, PhishingIndicator
from django.utils import timezone
import os

# Check if scikit-learn is available for ML-based detection
try:
    import sklearn
    ML_AVAILABLE = True
    print("ML libraries are available - ML-based detection is enabled")
except ImportError:
    ML_AVAILABLE = False
    print("ML libraries are not available - using rule-based detection only")

# More robust NLTK data handling
nltk_data_dir = os.path.join(os.path.expanduser('~'), 'nltk_data')
os.makedirs(nltk_data_dir, exist_ok=True)

# Set nltk data path explicitly to avoid permission issues
nltk.data.path.append(nltk_data_dir)

# Check if required NLTK resources are already downloaded
def ensure_nltk_data():
    resources_available = True
    
    # Just download punkt and check for its availability generically
    try:
        nltk.download('punkt', quiet=True)
        # Simple verification
        if nltk.tokenize.sent_tokenize("Hello world. This is a test."):
            print(f"NLTK resource 'punkt' is available")
            resources_available = True
        else:
            resources_available = False
    except Exception as e:
        print(f"Error with NLTK punkt: {str(e)}")
        resources_available = False
    
    return resources_available

# Try to ensure nltk data is available
NLTK_AVAILABLE = ensure_nltk_data()
print(f"NLTK data available for tokenization: {NLTK_AVAILABLE}")


def analyze_email(request):
    """View for analyzing an email"""
    
    if request.method == 'POST':
        email_subject = request.POST.get('email_subject', '').strip()
        email_body = request.POST.get('email_body', '').strip()
        email_sender = request.POST.get('email_sender', '').strip()
        
        if not email_body:
            messages.error(request, 'Please enter email content to analyze.')
            return redirect('email_analyzer:analyze')
        
        # Create a new analysis record
        analysis = EmailAnalysis(
            email_subject=email_subject,
            email_body=email_body,
            email_sender=email_sender,
            user=request.user if request.user.is_authenticated else None
        )
        
        # Perform the analysis
        perform_email_analysis(analysis)
        analysis.save()
        
        return redirect('email_analyzer:results', analysis_id=analysis.id)
    
    return render(request, 'email_analyzer/analyze.html')


def analysis_results(request, analysis_id):
    """View for displaying analysis results"""
    
    analysis = get_object_or_404(EmailAnalysis, id=analysis_id)
    
    # Check if the user has permission to view this analysis
    if analysis.user and request.user != analysis.user and not request.user.is_staff:
        messages.error(request, 'You do not have permission to view this analysis.')
        return redirect('email_analyzer:analyze')
    
    context = {
        'analysis': analysis,
    }
    
    return render(request, 'email_analyzer/results.html', context)


@csrf_exempt
def api_analyze_email(request):
    """API endpoint for analyzing an email"""
    
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST method is allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        email_subject = data.get('email_subject', '').strip()
        email_body = data.get('email_body', '').strip()
        email_sender = data.get('email_sender', '').strip()
        
        if not email_body:
            return JsonResponse({'error': 'Email body is required'}, status=400)
        
        # Create a new analysis record
        analysis = EmailAnalysis(
            email_subject=email_subject,
            email_body=email_body,
            email_sender=email_sender
        )
        
        # Perform the analysis
        perform_email_analysis(analysis)
        analysis.save()
        
        # Return the analysis results
        return JsonResponse({
            'analysis_id': analysis.id,
            'is_phishing': analysis.is_phishing,
            'confidence_score': analysis.confidence_score,
            'details': {
                'has_suspicious_links': analysis.has_suspicious_links,
                'suspicious_links': analysis.suspicious_links.split(',') if analysis.suspicious_links else [],
                'has_urgent_language': analysis.has_urgent_language,
                'urgent_phrases': analysis.urgent_phrases.split(',') if analysis.urgent_phrases else [],
                'has_misspellings': analysis.has_misspellings,
                'misspelled_words': analysis.misspelled_words.split(',') if analysis.misspelled_words else [],
                'has_suspicious_attachments': analysis.has_suspicious_attachments,
                'suspicious_attachments': analysis.suspicious_attachments.split(',') if analysis.suspicious_attachments else [],
                'has_spoofed_sender': analysis.has_spoofed_sender,
                'sender_in_blacklist': analysis.sender_in_blacklist,
                'sender_in_whitelist': analysis.sender_in_whitelist,
            }
        })
    
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


def perform_email_analysis(analysis):
    """Perform email analysis with NLP and pattern detection"""
    
    # Initialize analysis details
    analysis.has_suspicious_links = False
    analysis.has_urgent_language = False
    analysis.has_misspellings = False
    analysis.has_suspicious_attachments = False
    analysis.has_spoofed_sender = False
    
    try:
        # Extract links from email body using both HTML parsing and regex
        links = []
        
        # First try BeautifulSoup to find HTML links
        try:
            soup = BeautifulSoup(analysis.email_body, 'html.parser')
            html_links = [a.get('href') for a in soup.find_all('a', href=True)]
            links.extend(html_links)
        except Exception as e:
            print(f"BeautifulSoup parsing error: {str(e)}")
        
        # Also use regex to find plain text URLs that might not be in HTML tags
        url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+'
        text_links = re.findall(url_pattern, analysis.email_body)
        links.extend(text_links)
        
        # Remove duplicates
        links = list(set(links))
        
        # Check for suspicious links
        suspicious_links = []
        for link in links:
            # Check for IP address URLs
            if re.search(r'https?://\d+\.\d+\.\d+\.\d+', link):
                suspicious_links.append(link)
            
            # Check for URL shorteners
            shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly']
            if any(shortener in link for shortener in shorteners):
                suspicious_links.append(link)
            
            # Check for misleading domains - expanded list
            misleading_domains = [
                'paypa1', 'amaz0n', 'g00gle', 'faceb00k', 'app1e',
                'microsoft-support', 'secure-verification', 'account-verify',
                'banking-secure', 'verify-account', 'security-alert'
            ]
            if any(domain in link.lower() for domain in misleading_domains):
                suspicious_links.append(link)
                
            # Any domain with unusual TLDs
            suspicious_tlds = ['.tk', '.top', '.xyz', '.online', '.info', '.club']
            if any(tld in link.lower() for tld in suspicious_tlds):
                suspicious_links.append(link)
        
        analysis.has_suspicious_links = len(suspicious_links) > 0
        analysis.suspicious_links = ','.join(suspicious_links) if suspicious_links else None
        
        # Check for urgent language - expanded list
        urgent_phrases = [
            'urgent', 'immediate action', 'account suspended', 'verify your account',
            'security alert', 'unauthorized access', 'limited time', 'act now',
            'attention required', 'account limited', 'suspicious activity',
            'unusual activity', 'security breach', 'verify immediately',
            'account access', 'security measure', 'locked', 'suspension',
            'verify your information', 'confirm your details', '24 hours',
            'termination', 'permanently', 'restricted', 'frozen', 'closure',
            'failure to verify', 'restore access'
        ]
        found_urgent_phrases = []
        
        # Check both subject and body for urgent phrases
        email_text = (analysis.email_subject + " " + analysis.email_body).lower()
        
        for phrase in urgent_phrases:
            if phrase.lower() in email_text:
                found_urgent_phrases.append(phrase)
        
        analysis.has_urgent_language = len(found_urgent_phrases) > 0
        analysis.urgent_phrases = ','.join(found_urgent_phrases) if found_urgent_phrases else None
        
        # Check for misspellings (expanded list)
        misspelled_variants = {
            'recieved': 'received',
            'acount': 'account',
            'passw0rd': 'password',
            'securty': 'security',
            'informaton': 'information',
            'verfication': 'verification',
            'comfirm': 'confirm',
            'verifiy': 'verify',
            'verfy': 'verify',
            'immediatly': 'immediately',
            'suspention': 'suspension',
            'authetication': 'authentication',
            'notificaton': 'notification',
            'attatchment': 'attachment',
            'documentaton': 'documentation'
        }
        
        found_misspellings = []
        
        # Only attempt tokenization if NLTK data is available
        if NLTK_AVAILABLE:
            try:
                words = word_tokenize(email_text)
                for word in words:
                    word = word.lower()
                    if word in misspelled_variants:
                        found_misspellings.append(word)
            except Exception as e:
                print(f"Tokenization error despite NLTK being available: {str(e)}")
                # Fall back to simple string checking
                for misspelled in misspelled_variants:
                    if misspelled in email_text:
                        found_misspellings.append(misspelled)
        else:
            # If NLTK is not available, use simple string matching
            for misspelled in misspelled_variants:
                if misspelled in email_text:
                    found_misspellings.append(misspelled)
        
        analysis.has_misspellings = len(found_misspellings) > 0
        analysis.misspelled_words = ','.join(found_misspellings) if found_misspellings else None
        
        # Improved attachment detection
        suspicious_extensions = ['.exe', '.bat', '.js', '.vbs', '.scr', '.cmd', '.zip', '.rar', '.jar', '.pif']
        
        # Pattern for direct attachment mentions
        attachment_pattern = r'([a-zA-Z0-9_-]+\.(exe|bat|js|vbs|scr|cmd|zip|rar|jar|pif))'
        attachments = re.findall(attachment_pattern, analysis.email_body, re.IGNORECASE)
        
        found_attachments = []
        for attachment in attachments:
            found_attachments.append(attachment[0])
        
        # Also look for attachment indications in text
        attachment_keywords = ["attached file", "download attachment", "open attachment", 
                              "verification form", "attached document", "download file"]
        
        for keyword in attachment_keywords:
            if keyword.lower() in email_text:
                found_attachments.append(keyword)
                break
        
        analysis.has_suspicious_attachments = len(found_attachments) > 0
        analysis.suspicious_attachments = ','.join(found_attachments) if found_attachments else None
        
        # Check for sender spoofing (improved)
        legitimate_domains = ['paypal.com', 'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'amazon.com', 'apple.com']
        suspicious_sender_patterns = [
            r'.*@.*\d+\.com',  # Has numbers in domain
            r'.*@.*-.*\.com',  # Has hyphens in domain
            r'.*@.*(secure|verify|service|support|alert|security|account).*\.com',  # Generic service domains
        ]
        
        # Check for close misspellings of legitimate domains
        for domain in legitimate_domains:
            base_domain = domain.split('.')[0]
            if base_domain in analysis.email_sender and domain not in analysis.email_sender:
                analysis.has_spoofed_sender = True
                break
        
        # Set spoofed sender if matches suspicious patterns
        if not analysis.has_spoofed_sender:
            for pattern in suspicious_sender_patterns:
                if re.match(pattern, analysis.email_sender):
                    analysis.has_spoofed_sender = True
                    break
        
        # Calculate phishing confidence score
        score = 0
        
        if analysis.has_suspicious_links:
            score += 0.3 * min(len(suspicious_links), 3)
        
        if analysis.has_urgent_language:
            score += 0.2 * min(len(found_urgent_phrases), 3)
        
        if analysis.has_misspellings:
            score += 0.1 * min(len(found_misspellings), 5)
        
        if analysis.has_suspicious_attachments:
            score += 0.4 * min(len(found_attachments), 2)
        
        if analysis.has_spoofed_sender:
            score += 0.2
        
        # Determine if the email is likely a phishing attempt
        analysis.confidence_score = min(score, 1.0)
        analysis.is_phishing = analysis.confidence_score > 0.5
        
    except Exception as e:
        print(f"Error in email analysis: {str(e)}")
        # If there's an error, mark as potentially suspicious
        analysis.is_phishing = None
        analysis.confidence_score = None
