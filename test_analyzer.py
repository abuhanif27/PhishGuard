import os
import django

# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'phishguard_project.settings')
django.setup()

# Import the email analysis function and model
from email_analyzer.views import perform_email_analysis
from email_analyzer.models import EmailAnalysis

def test_phishing_email():
    print("Testing phishing email detection...")
    
    # Create a known phishing email
    test_email = EmailAnalysis(
        email_subject="URGENT: Your PayPal Account Has Been Limited",
        email_sender="security-alerts@paypa1-services.com",
        email_body="""
Dear Valued Customer,

We have detected suspicious activity on your PayPal account. Your account has been temporarily limited for security reasons.

You must verify your account informaton immediately or it will be permanently suspended. Click on the link below to restore your account access:

http://paypa1-secure-verification.com/restore-account

Please note that failure to verify your account within 24 hours will result in permanent account closure and your funds will be frozen.

Attachment: Account_Verification_Form.exe

We appreciate your immediate attention to this urgent matter.

Regards,
PayPal Security Team
security_department@paypa1-services.com
        """
    )
    
    # Analyze the email
    perform_email_analysis(test_email)
    
    # Print results
    print(f"\nAnalysis Results:")
    print(f"Is Phishing: {test_email.is_phishing}")
    print(f"Confidence Score: {test_email.confidence_score}")
    print(f"\nDetected Indicators:")
    
    if test_email.has_suspicious_links:
        print(f"✓ Suspicious Links: {test_email.suspicious_links}")
    else:
        print("✗ No suspicious links detected")
        
    if test_email.has_urgent_language:
        print(f"✓ Urgent Language: {test_email.urgent_phrases}")
    else:
        print("✗ No urgent language detected")
        
    if test_email.has_misspellings:
        print(f"✓ Misspellings: {test_email.misspelled_words}")
    else:
        print("✗ No misspellings detected")
        
    if test_email.has_suspicious_attachments:
        print(f"✓ Suspicious Attachments: {test_email.suspicious_attachments}")
    else:
        print("✗ No suspicious attachments detected")
        
    if test_email.has_spoofed_sender:
        print(f"✓ Spoofed Sender Detected")
    else:
        print("✗ No sender spoofing detected")
    
    return test_email.is_phishing

if __name__ == "__main__":
    result = test_phishing_email()
    
    if result:
        print("\n✅ Phishing detection is working properly!")
    else:
        print("\n⚠️ Phishing detection failed to identify the test email!") 