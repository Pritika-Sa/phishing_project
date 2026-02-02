import pandas as pd
import os

# Define the path to the directory containing your CSV files
data_dir = r'C:\Users\Pritika_2\Downloads\archive'  # Update with your actual path

# List to hold DataFrames
dataframes = []

# Load each CSV file in the directory
for file in os.listdir(data_dir):
    if file.endswith('.csv'):
        file_path = os.path.join(data_dir, file)
        # Read the CSV file
        df = pd.read_csv(file_path)
        # Append the DataFrame to the list
        dataframes.append(df)

# Combine all DataFrames into one
combined_df = pd.concat(dataframes, ignore_index=True)

# Display the first few rows of the combined DataFrame
print("Combined DataFrame:")
print(combined_df.head())

# Data Cleaning
# Remove duplicates
combined_df.drop_duplicates(inplace=True)

# Handle missing values (you can customize this based on your needs)
combined_df.fillna('', inplace=True)

# Basic Analysis
# Count the number of occurrences of each label
label_counts = combined_df['label'].value_counts()
print("\nLabel Counts:")
print(label_counts)

# Feature Extraction
# Add a new column for the length of the email body
combined_df['body_length'] = combined_df['body'].apply(len)

# Display the first few rows of the updated DataFrame
print("\nUpdated DataFrame with body length:")
print(combined_df.head())

# Save the cleaned DataFrame to a new CSV file
cleaned_file_path = os.path.join(data_dir, 'cleaned_data.csv')
combined_df.to_csv(cleaned_file_path, index=False)
print(f"\nCleaned data saved to {cleaned_file_path}")
