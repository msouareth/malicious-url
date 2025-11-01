from flask import Flask, render_template, request, jsonify
import tensorflow as tf
import numpy as np
import re
from urllib.parse import urlparse
import pickle
import tldextract

app = Flask(__name__)

# Load the LSTM model
model = tf.keras.models.load_model('LSTM.h5')

# Class labels
CLASS_LABELS = ['benign', 'defacement', 'phishing', 'malware']

# Known safe domains (can be expanded)
SAFE_DOMAINS = {
    'nytimes.com', 'stackoverflow.com', 'openai.com', 'researchgate.net',
    'google.com', 'paypal.com', 'microsoft.com', 'apple.com',
    'amazon.com', 'facebook.com', 'twitter.com', 'linkedin.com',
    'github.com', 'youtube.com', 'wikipedia.org', 'microsoft.com',
    'apple.com', 'amazon.com', 'facebook.com', 'twitter.com',
    'linkedin.com', 'github.com', 'youtube.com', 'wikipedia.org',
    'spotify.com', 'open.spotify.com',  # Added Spotify domains
    'netflix.com', 'reddit.com', 'medium.com', 'quora.com',
    'dropbox.com', 'slack.com', 'zoom.us', 'discord.com',
    'trello.com', 'notion.so', 'figma.com', 'adobe.com'
}

# Known phishing patterns
PHISHING_PATTERNS = [
    r'secure-login-[a-zA-Z0-9]+\.com',
    r'[a-zA-Z0-9]+\.secure-login\.',
    r'[a-zA-Z0-9]+\.fake-site\.',
    r'[a-zA-Z0-9]+-login\.',
    r'[a-zA-Z0-9]+-auth-',
    r'[a-zA-Z0-9]+-support\.',
    r'[a-zA-Z0-9]+-manageacc\.',
    r'[a-zA-Z0-9]+-updatebilling\.',
    r'[a-zA-Z0-9]+-update\.',
    r'[a-zA-Z0-9]+-verification\.',
    r'[a-zA-Z0-9]+-account\.',
    r'[a-zA-Z0-9]+-login\.',
    r'[a-zA-Z0-9]+-signin\.',
    r'[a-zA-Z0-9]+-verify\.',
    r'[a-zA-Z0-9]+-confirm\.',
    r'[a-zA-Z0-9]+-security\.',
    r'[a-zA-Z0-9]+-validate\.',
    # Add more specific patterns for common phishing attempts
    r'[a-zA-Z0-9]+\.account-recovery-',
    r'[a-zA-Z0-9]+\.user-verification\.',
    r'[a-zA-Z0-9]+\.secure-session\.',
    r'[a-zA-Z0-9]+\.login-secure\.',
    r'[a-zA-Z0-9]+\.update-info\.',
    r'[a-zA-Z0-9]+\.validate\?',
    r'[a-zA-Z0-9]+\.login\/validate\?',
    r'[a-zA-Z0-9]+\.support-system\.',
    r'[a-zA-Z0-9]+\.recovery-system\.',
    # Add patterns for financial institution spoofing
    r'paypal\.com\.[a-zA-Z0-9-]+\.',
    r'chasebank\.[a-zA-Z0-9-]+\.',
    r'nationalbank\.[a-zA-Z0-9-]+\.',
    r'bankofamerica\.[a-zA-Z0-9-]+\.',
    r'wellsfargo\.[a-zA-Z0-9-]+\.',
    r'citibank\.[a-zA-Z0-9-]+\.',
    r'hsbc\.[a-zA-Z0-9-]+\.',
    r'barclays\.[a-zA-Z0-9-]+\.'
]

# Known defacement indicators and patterns
DEFACEMENT_PATTERNS = [
    r'hacked-by-[a-zA-Z0-9]+',
    r'defacement=true',
    r'msg=hacked_by_[a-zA-Z0-9_]+',
    r'defaced-page\.html',
    r'notice=site-defaced',
    r'404-hacked',
    r'zone-h\.org',
    r'defaced\.',
    r'hacked\.',
    r'hacked\.html',
    r'hacked\.htm',
    r'defaced\.html',
    r'defaced\.htm',
    r'mirror\.zone-h\.org',
    r'mirror-h\.org',
    r'sytes\.net',
    r'alldebrid\.com',
    # Add more specific defacement patterns
    r'author=anonymous',
    r'uid=guest\d+',
    r'news\.php\?article=\d+',
    r'university\.edu/news\.php'
]

# Lower the confidence threshold to catch more potential threats
CONFIDENCE_THRESHOLD = 0.65

def is_known_safe_domain(url):
    """Check if the domain is in our known safe list"""
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"
    return domain in SAFE_DOMAINS

def is_defacement_url(url):
    """Check if the URL contains defacement indicators"""
    url = url.lower()
    
    # Check for known defacement patterns
    if any(re.search(pattern, url) for pattern in DEFACEMENT_PATTERNS):
        return True
    
    # Check for suspicious domain structures
    parts = url.split('/')
    if len(parts) > 2:
        domain = parts[2]
        # Check for suspicious subdomains
        if 'hacked.' in domain or 'defaced.' in domain or 'mirror.' in domain:
            return True
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.org', '.net', '.biz']
        if any(tld in domain for tld in suspicious_tlds):
            return True
    
    return False

def is_phishing_url(url):
    """Check if the URL contains phishing indicators"""
    url = url.lower()
    
    # Check for known phishing patterns
    if any(re.search(pattern, url) for pattern in PHISHING_PATTERNS):
        return True
    
    # Check for domain spoofing (e.g., paypal.com.user-verification...)
    parts = url.split('/')
    if len(parts) > 2:
        domain = parts[2]
        if '.' in domain:
            subdomains = domain.split('.')
            # Check if a legitimate financial domain is used as a subdomain
            financial_domains = ['paypal', 'chase', 'bank', 'wells', 'citi', 'hsbc', 'barclays']
            for i in range(len(subdomains) - 1):
                if any(financial in subdomains[i].lower() for financial in financial_domains):
                    return True
    
    return False

def clean_url(url):
    """Clean and normalize the URL"""
    # Replace hxxp:// or hxxps:// with http:// or https://
    url = re.sub(r'^hxxps?://', 'https://', url)
    
    # Replace [.] with .
    url = url.replace('[.]', '.')
    
    # Replace (.) with .
    url = url.replace('(.)', '.')
    
    # Replace {.} with .
    url = url.replace('{.}', '.')
    
    # Replace [dot] with .
    url = url.replace('[dot]', '.')
    
    # Replace (dot) with .
    url = url.replace('(dot)', '.')
    
    # Replace {dot} with .
    url = url.replace('{dot}', '.')
    
    return url

def preprocess_url(url):
    # Clean the URL first
    url = clean_url(url)
    
    # Convert to lowercase
    url = url.lower()
    
    # Remove http:// or https://
    url = re.sub(r'^https?://', '', url)
    
    # Remove www.
    url = re.sub(r'^www\.', '', url)
    
    # Remove trailing slash
    url = url.rstrip('/')
    
    # For known safe domains, keep the full URL structure
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"
    if domain in SAFE_DOMAINS:
        # For safe domains, only remove tracking parameters
        url = re.sub(r'utm_[^&]+', '', url)
        return np.array([ord(char) for char in url]).reshape(1, -1)
    
    # For other domains, apply stricter preprocessing
    # Keep URL parameters as they might contain malicious indicators
    # Only remove common tracking parameters
    url = re.sub(r'utm_[^&]+', '', url)
    
    # Keep special characters as they might be part of malicious patterns
    # Only remove spaces and tabs
    url = re.sub(r'[\s\t]', '', url)
    
    # Tokenize the URL
    tokens = list(url)
    
    # Convert characters to ASCII values
    ascii_values = [ord(char) for char in tokens]
    
    # Pad or truncate to fixed length (e.g., 200)
    max_length = 200
    if len(ascii_values) > max_length:
        ascii_values = ascii_values[:max_length]
    else:
        ascii_values.extend([0] * (max_length - len(ascii_values)))
    
    return np.array(ascii_values).reshape(1, max_length)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/predict', methods=['POST'])
def predict():
    try:
        url = request.json['url']
        
        # Clean the URL before processing
        cleaned_url = clean_url(url)
        
        # Extract domain for checking
        extracted = tldextract.extract(cleaned_url)
        domain = f"{extracted.domain}.{extracted.suffix}"
        
        # Check if it's a known safe domain
        if domain in SAFE_DOMAINS:
            return jsonify({
                'is_malicious': False,
                'threat_type': 'benign',
                'confidence': 1.0,
                'message': 'URL is from a known safe domain.',
                'result_type': 'safe'
            })
        
        # Check if it's a phishing URL first (since phishing is more specific)
        if is_phishing_url(cleaned_url):
            return jsonify({
                'is_malicious': True,
                'threat_type': 'phishing',
                'confidence': 1.0,
                'message': 'URL contains known phishing indicators.',
                'result_type': 'malicious'
            })
        
        # Then check for defacement
        if is_defacement_url(cleaned_url):
            return jsonify({
                'is_malicious': True,
                'threat_type': 'defacement',
                'confidence': 1.0,
                'message': 'URL contains known defacement indicators.',
                'result_type': 'malicious'
            })
        
        # Preprocess the URL
        processed_url = preprocess_url(cleaned_url)
        
        # Make prediction
        prediction = model.predict(processed_url)
        
        # Get the predicted class and confidence
        predicted_class = np.argmax(prediction[0])
        confidence = float(prediction[0][predicted_class])
        
        # Get the threat type
        threat_type = CLASS_LABELS[predicted_class]
        
        # Determine if URL is malicious
        is_malicious = predicted_class != 0  # 0 is benign
        
        # If confidence is below threshold, mark as suspicious
        if confidence < CONFIDENCE_THRESHOLD:
            is_malicious = True
            threat_type = 'suspicious'
            message = "URL shows suspicious characteristics. Please verify manually."
        else:
            if is_malicious:
                message = f"URL appears to be malicious ({threat_type})."
            else:
                message = "URL appears to be safe."
        
        return jsonify({
            'is_malicious': bool(is_malicious),
            'threat_type': str(threat_type),
            'confidence': float(confidence),
            'message': str(message),
            'result_type': 'malicious' if is_malicious else 'safe'
        })
        
    except Exception as e:
        return jsonify({
            'is_malicious': True,
            'threat_type': 'error',
            'confidence': 0.0,
            'message': f'Error analyzing URL: {str(e)}',
            'result_type': 'malicious'
        })

if __name__ == '__main__':
    app.run(debug=True)