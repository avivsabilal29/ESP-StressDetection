import pandas as pd
import re
from sklearn.neighbors import KNeighborsClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

# Function to clean and extract BPM and temperature data
def clean_data(data):
    bpm_values = []
    temp_values = []
    for row in data:
        bpm_match = re.search(r'BPM=(\d+\.\d+)', row)
        temp_match = re.search(r'Temperature=(\d+\.\d+)', row)
        if bpm_match:
            bpm = float(bpm_match.group(1))
            temp = 0.0  # Default value for temperature if not found
            if temp_match:
                temp = float(temp_match.group(1))
            bpm_values.append(bpm)
            temp_values.append(temp)
    return bpm_values, temp_values

# Define conditions based on the given table
def classify_condition(row):
    if row['BPM'] >= 100:
        if row['Temperature'] > 33:
            return 'Stressed'
        elif row['Temperature'] <= 33 and row['Temperature'] >= 32:
            return 'Tense'
    elif row['BPM'] >= 70 and row['BPM'] < 100:
        if row['Temperature'] <= 36 and row['Temperature'] >= 35:
            return 'Calm'
    elif row['BPM'] >= 60 and row['BPM'] < 70:
        if row['Temperature'] <= 37 and row['Temperature'] >= 36:
            return 'Relaxed'
    return 'Unknown'

# Read the raw data file
file_path = 'heartRate.csv'
with open(file_path, 'r') as file:
    raw_data = file.readlines()

# Clean the data and extract BPM and temperature values
bpm_values, temp_values = clean_data(raw_data)

# Create a DataFrame from the cleaned data
cleaned_df = pd.DataFrame({
    'BPM': bpm_values,
    'Temperature': temp_values
})

# Remove rows with BPM less than 60, greater than 120, or any zero values
cleaned_df = cleaned_df[(cleaned_df['BPM'] >= 60) & (cleaned_df['BPM'] <= 120) & (cleaned_df['BPM'] != 0)]

# For demonstration, adding dummy temperature values since temperature data is missing
cleaned_df['Temperature'] = cleaned_df['Temperature'].replace(0, 36)

# Apply condition classification
cleaned_df['Condition'] = cleaned_df.apply(classify_condition, axis=1)

# Remove rows with 'Unknown' condition
cleaned_df = cleaned_df[cleaned_df['Condition'] != 'Unknown']

# Save the cleaned and classified data to a new CSV file
cleaned_df.to_csv('classified_heart_rate_data.csv', index=False)

# Print classification report
X = cleaned_df[['BPM', 'Temperature']]
y = cleaned_df['Condition']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
knn = KNeighborsClassifier(n_neighbors=3)
knn.fit(X_train, y_train)
y_pred = knn.predict(X_test)
print(classification_report(y_test, y_pred))
