import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import joblib

# Synthetic dataset for demonstration/fallback
data = {
    'body': [
        "Please verify your account immediately or it will be suspended.",
        "Click here to claim your lottery prize!",
        "Your bank account has been compromised. Login now.",
        "Meeting at 3 PM in the conference room.",
        "Hey, are we still on for lunch?",
        "Project update attached. Please review.",
        "URGENT: Password reset required.",
        "Get rich quick! Investment opportunity.",
        "Happy birthday! Hope you have a great day.",
        "The invoice for last month is attached."
    ],
    'label': [
        'Phishing', 'Phishing', 'Phishing', 
        'Legitimate', 'Legitimate', 'Legitimate', 
        'Phishing', 'Phishing', 
        'Legitimate', 'Legitimate'
    ]
}

df = pd.DataFrame(data)

print("Training dummy model on synthetic data...")

# Vectorizer
tfidf_vectorizer = TfidfVectorizer(stop_words='english')
X = tfidf_vectorizer.fit_transform(df['body'])

# Model
model = RandomForestClassifier(n_estimators=10, random_state=42)
model.fit(X, df['label'])

# Save
joblib.dump(model, 'phishing_detection_model.pkl')
joblib.dump(tfidf_vectorizer, 'tfidf_vectorizer.pkl')

print("New dummy model and vectorizer saved successfully.")
print("Feature names sample:", tfidf_vectorizer.get_feature_names_out()[:10])
print("Model classes:", model.classes_)
