import pandas as pd
import re
import os
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report, confusion_matrix
import joblib

# Load datasets from archive folder
archive_dir = r'D:\4. PROJECTS\phishing\link-sights-stay-safe-online\archive'
dataframes = []

print(f"Loading datasets from {archive_dir}...")
for file in os.listdir(archive_dir):
    if file.endswith('.csv'):
        file_path = os.path.join(archive_dir, file)
        try:
            print(f"Loading {file}...")
            df = pd.read_csv(file_path, on_bad_lines='skip')
            dataframes.append(df)
            print(f"  ✓ Loaded {len(df)} rows")
        except Exception as e:
            print(f"  ✗ Error loading {file}: {e}")

# Combine all dataframes
print("\nCombining datasets...")
data = pd.concat(dataframes, ignore_index=True)
print(f"Total rows: {len(data)}")

# Print the shape of the dataset
print(f"\nDataset Info:")
print(f"Shape: {data.shape}")
print(f"Columns: {list(data.columns)}")

# Identify email body column (could be 'body', 'text', 'email', 'content', etc.)
body_columns = ['body', 'text', 'email', 'content', 'message', 'email_body']
body_col = None
for col in body_columns:
    if col in data.columns:
        body_col = col
        break

if body_col is None:
    # If no standard column found, use the first text column
    body_col = data.columns[0]
    print(f"Warning: Using '{body_col}' as email content column")
else:
    print(f"Using '{body_col}' as email content column")

# Identify label column
label_columns = ['label', 'class', 'is_phishing', 'phishing', 'spam']
label_col = None
for col in label_columns:
    if col in data.columns:
        label_col = col
        break

if label_col is None:
    # If no standard column found, use the last column
    label_col = data.columns[-1]
    print(f"Warning: Using '{label_col}' as label column")
else:
    print(f"Using '{label_col}' as label column")

# Check for missing values in the body column
print(f"\nMissing values in '{body_col}': {data[body_col].isnull().sum()}")

# Fill NaN values with an empty string
data[body_col] = data[body_col].fillna('')
print(f"Filled NaN values in '{body_col}'")

# Preprocess the data
def preprocess(text):
    # Ensure text is a string
    if isinstance(text, str):
        text = text.lower()
        text = re.sub(r'<.*?>', '', text)
        text = re.sub(r'http\S+|www\S+|https\S+', '', text, flags=re.MULTILINE)
        text = re.sub(r'[^a-zA-Z\s]', '', text)
        text = re.sub(r'\s+', ' ', text).strip()
        return text
    else:
        return ''  # Return an empty string if not a string

# Clean the body text
print(f"\nStarting text preprocessing...")
data['cleaned_body'] = data[body_col].apply(preprocess)
print("Completed text preprocessing.")

# Initialize the TF-IDF vectorizer
tfidf_vectorizer = TfidfVectorizer()

# Fit and transform the cleaned body text to get the feature matrix
X = tfidf_vectorizer.fit_transform(data['cleaned_body'])
print("TF-IDF vectorization complete.")

# Get the target labels
y = data[label_col]

# Handle label values (convert to 0/1 if needed)
if y.dtype == 'object':  # If labels are strings
    # Try to convert string labels to binary
    y = y.apply(lambda x: 1 if str(x).lower() in ['1', 'phishing', 'spam', 'true', 'malicious'] else 0)

print(f"Label distribution:")
print(y.value_counts())

# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
print("Data split into training and testing sets.")

# Initialize the model
model = RandomForestClassifier(n_estimators=300, random_state=42, n_jobs=-1, verbose=1)
print(f"\nModel: Random Forest Classifier with 300 trees")

# Train the model
print("Starting model training...")
model.fit(X_train, y_train)
print("Model training complete.")

# Make predictions on the test set
y_pred = model.predict(X_test)

# Evaluate the model
print(confusion_matrix(y_test, y_pred))
print(classification_report(y_test, y_pred))

# Save the model and vectorizer to the project directory
model_path = r'D:\4. PROJECTS\phishing\link-sights-stay-safe-online\phishing_detection_model.pkl'
vectorizer_path = r'D:\4. PROJECTS\phishing\link-sights-stay-safe-online\tfidf_vectorizer.pkl'

joblib.dump(model, model_path)
joblib.dump(tfidf_vectorizer, vectorizer_path)

print(f"\n✓ Model saved to: {model_path}")
print(f"✓ Vectorizer saved to: {vectorizer_path}")
print("Model retraining complete!")
