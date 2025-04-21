import numpy as np
import tensorflow as tf
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense, Dropout
from tensorflow.keras.optimizers import Adam
import joblib
import os

from preprocess import preprocess_data

def build_autoencoder(input_dim):
    input_layer = Input(shape=(input_dim,))
    encoded = Dense(64, activation='relu')(input_layer)
    encoded = Dropout(0.2)(encoded)
    encoded = Dense(32, activation='relu')(encoded)
    decoded = Dense(64, activation='relu')(encoded)
    decoded = Dense(input_dim, activation='linear')(decoded)

    autoencoder = Model(input_layer, decoded)
    autoencoder.compile(optimizer=Adam(0.001), loss='mse')
    return autoencoder

dataset_path = os.path.abspath("./dataset/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
X, y = preprocess_data(dataset_path)
X_normal = X[y == 0]  # Train only on normal traffic

train_size = int(0.8 * len(X_normal))
X_train, X_val = X_normal[:train_size], X_normal[train_size:]

model = build_autoencoder(X_train.shape[1])
history = model.fit(X_train, X_train, epochs=50, batch_size=64, validation_data=(X_val, X_val), verbose=1)

models_dir = os.path.abspath("./models")
os.makedirs(models_dir, exist_ok=True)

model.save(os.path.join(models_dir, "autoencoder_model.h5"))

reconstructions = model.predict(X_val)
mse = np.mean(np.power(X_val - reconstructions, 2), axis=1)
threshold = np.mean(mse) + 3 * np.std(mse)

joblib.dump(threshold, os.path.join(models_dir, "threshold.pkl"))

print("✅ Model and threshold saved successfully!")
