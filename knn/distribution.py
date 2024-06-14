import pandas as pd
import matplotlib.pyplot as plt

# Load the classified data
classified_file_path = 'classified_heart_rate_data.csv'
df = pd.read_csv(classified_file_path)

# Calculate mean BPM and Temperature
mean_bpm = df['BPM'].mean()
mean_temp = df['Temperature'].mean()

# Plot histogram of BPM values
plt.figure(figsize=(10, 6))
plt.hist(df['BPM'], bins=20, edgecolor='black')
plt.axvline(mean_bpm, color='red', linestyle='dashed', linewidth=1)
plt.title('Distribution of BPM Values')
plt.xlabel('BPM')
plt.ylabel('Frequency')
plt.grid(True)
plt.show()

# Plot histogram of Temperature values
plt.figure(figsize=(10, 6))
plt.hist(df['Temperature'], bins=20, edgecolor='black')
plt.axvline(mean_temp, color='red', linestyle='dashed', linewidth=1)
plt.title('Distribution of Temperature Values')
plt.xlabel('Temperature (°C)')
plt.ylabel('Frequency')
plt.grid(True)
plt.show()

# Plot histogram of BPM values for each condition
plt.figure(figsize=(12, 8))
conditions = df['Condition'].unique()
for condition in conditions:
    subset = df[df['Condition'] == condition]
    plt.hist(subset['BPM'], bins=20, alpha=0.5, label=condition)
plt.title('Distribution of BPM Values by Condition')
plt.xlabel('BPM')
plt.ylabel('Frequency')
plt.legend(loc='upper right')
plt.grid(True)
plt.show()

# Plot histogram of Temperature values for each condition
plt.figure(figsize=(12, 8))
for condition in conditions:
    subset = df[df['Condition'] == condition]
    plt.hist(subset['Temperature'], bins=20, alpha=0.5, label=condition)
plt.title('Distribution of Temperature Values by Condition')
plt.xlabel('Temperature (°C)')
plt.ylabel('Frequency')
plt.legend(loc='upper right')
plt.grid(True)
plt.show()
