import re
import joblib
import nltk
import whois
import tldextract
import numpy as np
import streamlit as st
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
from urllib.parse import urlparse

# Download necessary NLTK data (if not available)
nltk.download("stopwords")
nltk.download("punkt")
nltk.download("wordnet")
nltk.download("punkt_tab")

# Load trained model and vectorizer
try:
    model = joblib.load("optimized_scam_detection_model.pkl")
    vectorizer = joblib.load("vectorizer.pkl")
except FileNotFoundError:
    st.error("❌ Model files not found! Please ensure 'optimized_scam_detection_model.pkl' and 'vectorizer.pkl' exist.")

# Common spam keywords (for quick rule-based detection)
SPAM_KEYWORDS = [
    "free money", "urgent action", "congratulations", "you won", "click here",
    "exclusive offer", "limited time", "password reset", "bank alert", "lottery"
]

# Step 1: Improved Text Preprocessing
lemmatizer = WordNetLemmatizer()

def preprocess_text(text):
    text = text.lower()
    text = re.sub(r"http\S+|www\S+|https\S+", "", text)  # Remove URLs
    text = re.sub(r"\S+@\S+", "", text)  # Remove emails
    text = re.sub(r"\d+", "", text)  # Remove numbers
    text = re.sub(r"\W", " ", text)  # Remove special characters
    tokens = word_tokenize(text)
    tokens = [lemmatizer.lemmatize(word) for word in tokens if word not in stopwords.words("english")]
    return " ".join(tokens)

# Step 2: Advanced URL Analysis
def extract_url_features(url):
    features = {}
    try:
        domain_info = whois.whois(urlparse(url).netloc)
        features["Domain Age (days)"] = (domain_info.expiration_date - domain_info.creation_date).days if domain_info.creation_date else -1
    except:
        features["Domain Age (days)"] = -1

    extracted_url = tldextract.extract(url)
    features["Subdomain Count"] = len(extracted_url.subdomain.split(".")) if extracted_url.subdomain else 0
    features["URL Length"] = len(url)
    features["Contains IP"] = "Yes" if re.match(r"\d+\.\d+\.\d+\.\d+", url) else "No"

    return features

# Step 3: Streamlit UI
st.title("AI-Powered Phishing & Scam Detection")
st.write("Enter a **text message** or a **URL** to check if it's a phishing attempt.")

# User input
user_input = st.text_area("Enter text or URL:", "")

if st.button("🔍 Detect Scam"):
    if user_input:
        # Preprocess text
        cleaned_text = preprocess_text(user_input)

        # Check for spam keywords
        scam_reason = None
        for keyword in SPAM_KEYWORDS:
            if keyword in cleaned_text:
                scam_reason = f"⚠️ Contains suspicious keyword: '{keyword}'"
                break

        # If it's a URL, extract additional features
        url_features = None
        if user_input.startswith("http"):
            url_features = extract_url_features(user_input)

        # Convert text to TF-IDF features
        text_vector = vectorizer.transform([cleaned_text])

        # Predict using AI model
        prediction_proba = model.predict_proba(text_vector)[0][1]  # Probability of scam
        scam_detected = prediction_proba > 0.5  # If probability > 50%, mark as scam

        # Display results
        st.subheader("🔍 Detection Results")
        st.write(f"**Input:** {user_input}")
        if scam_detected:
           st.error(f"🚨 Scam Detected! (Confidence: {round(prediction_proba * 100, 2)}%)")
        else:
            st.success(f"✅ No Scam Detected (Confidence: {round(prediction_proba * 100, 2)}%)")

        # Show URL features (if applicable)
        if url_features:
            st.subheader("🔗 URL Analysis")
            st.json(url_features)
    else:
        st.error("⚠️ Please enter a text or URL to analyze.")

