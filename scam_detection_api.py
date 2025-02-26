import re
import joblib
import nltk
import whois
import tldextract
import numpy as np
from flask import Flask, request, jsonify
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords, wordnet
from nltk.stem import WordNetLemmatizer
from urllib.parse import urlparse

# Download necessary NLTK data
nltk.download('stopwords')
nltk.download('punkt')
nltk.download('wordnet')
nltk.download('punkt_tab')

# Load trained model and vectorizer
try:
    model = joblib.load("optimized_scam_detection_model.pkl")
    vectorizer = joblib.load("vectorizer.pkl")
except FileNotFoundError:
    raise FileNotFoundError("❌ Trained model not found. Please train and save 'optimized_scam_detection_model.pkl'.")

# Initialize Flask app
app = Flask(__name__)

# Common spam keywords (for quick rule-based detection)
SPAM_KEYWORDS = [
    "free money", "urgent action", "congratulations", "you won", "click here", 
    "exclusive offer", "limited time", "password reset", "bank alert", "lottery"
]

### **Step 1: Improved Text Preprocessing**
lemmatizer = WordNetLemmatizer()

def preprocess_text(text):
    text = text.lower()
    text = re.sub(r"http\S+|www\S+|https\S+", "", text)  # Remove URLs
    text = re.sub(r"\S+@\S+", "", text)  # Remove emails
    text = re.sub(r"\d+", "", text)  # Remove numbers
    text = re.sub(r'\W', ' ', text)  # Remove special characters
    tokens = word_tokenize(text)
    tokens = [lemmatizer.lemmatize(word) for word in tokens if word not in stopwords.words("english")]
    return " ".join(tokens)

### **Step 2: Advanced URL Analysis**
def extract_url_features(url):
    features = {}
    try:
        domain_info = whois.whois(urlparse(url).netloc)
        features["domain_age"] = (domain_info.expiration_date - domain_info.creation_date).days if domain_info.creation_date else -1
    except:
        features["domain_age"] = -1

    extracted_url = tldextract.extract(url)
    features["subdomain_count"] = len(extracted_url.subdomain.split(".")) if extracted_url.subdomain else 0
    features["url_length"] = len(url)
    features["has_ip"] = 1 if re.match(r"\d+\.\d+\.\d+\.\d+", url) else 0

    return features

### **Step 3: API Route for Scam Detection**
@app.route('/detect_scam', methods=['POST'])
def detect_scam():
    data = request.json
    text = data.get("text", "")
    
    if not text:
        return jsonify({"error": "No text provided"}), 400
    
    # Preprocess text
    cleaned_text = preprocess_text(text)

    # Check for spam keywords
    for keyword in SPAM_KEYWORDS:
        if keyword in cleaned_text:
            return jsonify({
                "input_text": text,
                "scam_detected": True,
                "confidence_score": 0.9,
                "reason": f"Contains suspicious keyword: '{keyword}'"
            })

    # If input is a URL, extract additional features
    url_features = None
    if text.startswith("http"):
        url_features = extract_url_features(text)

    # Convert text to TF-IDF features
    text_vector = vectorizer.transform([cleaned_text])
    
    # Predict using AI model
    prediction_proba = model.predict_proba(text_vector)[0][1]  # Probability of scam
    scam_detected = prediction_proba > 0.5  # If probability > 50%, mark as scam

    result = {
        "input_text": text,
        "scam_detected": bool(scam_detected),
        "confidence_score": round(float(prediction_proba), 2),
        "reason": "AI model detected scam patterns." if scam_detected else "No scam detected."
    }

    if url_features:
        result.update(url_features)

    return jsonify(result)

# Run Flask API
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
