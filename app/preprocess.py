import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
import joblib
import os

def preprocess_data(file_path, save_scaler=True):
    """Loads and preprocesses dataset for training."""
    data = pd.read_csv(file_path)

    # Drop unnecessary columns
    drop_cols = ['Flow ID', ' Source IP', ' Destination IP', ' Timestamp']
    data.drop(columns=[col for col in drop_cols if col in data.columns], inplace=True, errors="ignore")

    # Convert labels: "BENIGN" = 0, Attacks = 1
    data[' Label'] = data[' Label'].apply(lambda x: 0 if 'BENIGN' in x else 1)

    # Handle missing values
    data.replace([np.inf, -np.inf], np.nan, inplace=True)
    data.fillna(data.mean(), inplace=True)

    # Extract features
    X = data.drop(columns=[' Label']).values
    scaler = StandardScaler().fit(X)

    if save_scaler:
        os.makedirs("./models", exist_ok=True)
        joblib.dump(scaler, './models/scaler.pkl')

    return X, data[' Label'].values



if __name__ == "__main__":
    preprocess_data("./dataset/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
