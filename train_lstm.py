"""
train_lstm.py
=============
Stage 2 of the pipeline.

Builds fixed-length ordered sequences from mock_nids_traffic.csv and trains
an LSTM binary classifier for intrusion detection.

Run: python train_lstm.py
Output: lstm_ids.keras

Notes:
- This script uses TensorFlow/Keras.
- It treats each row in mock_nids_traffic.csv as one timestep.
- Sequences are labeled attack if any row inside the window has label = 1.
"""

from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler

from tensorflow import keras
from tensorflow.keras import layers


RAW_CSV = "mock_nids_traffic.csv"
MODEL_OUT = "lstm_ids.keras"
SCALER_OUT = "lstm_ids_scaler.joblib"

SEQUENCE_LENGTH = 10
FEATURE_COLUMNS = [
    "packet_count",
    "byte_count",
    "duration",
    "flag_syn",
    "flag_ack",
    "dest_port",
]


def load_raw_data(path):
    df = pd.read_csv(path, parse_dates=["timestamp"])
    df = df.sort_values("timestamp").reset_index(drop=True)
    return df


def build_sequences(df, sequence_length=SEQUENCE_LENGTH):
    sequences = []
    labels = []

    if len(df) < sequence_length:
        return np.empty((0, sequence_length, len(FEATURE_COLUMNS))), np.empty((0,))

    scaler = MinMaxScaler()
    feature_matrix = scaler.fit_transform(df[FEATURE_COLUMNS].astype(float))

    for start_index in range(0, len(df) - sequence_length + 1):
        end_index = start_index + sequence_length
        window = feature_matrix[start_index:end_index]
        window_labels = df.iloc[start_index:end_index]["label"].astype(int)
        sequences.append(window)
        labels.append(int(window_labels.max()))

    return np.array(sequences, dtype=float), np.array(labels, dtype=int)


def build_model(input_shape):
    model = keras.Sequential([
        layers.Input(shape=input_shape),
        layers.LSTM(64, return_sequences=True),
        layers.Dropout(0.2),
        layers.LSTM(32),
        layers.Dropout(0.2),
        layers.Dense(16, activation="relu"),
        layers.Dense(1, activation="sigmoid"),
    ])

    model.compile(
        optimizer="adam",
        loss="binary_crossentropy",
        metrics=["accuracy"],
    )
    return model


def train_and_save(sequence_array, label_array):
    if len(sequence_array) == 0:
        raise ValueError(
            "Not enough rows to build sequences. Add more traffic or reduce SEQUENCE_LENGTH."
        )

    if len(np.unique(label_array)) < 2:
        raise ValueError(
            "Need both normal and attack labels to train the LSTM classifier."
        )

    X_train, X_test, y_train, y_test = train_test_split(
        sequence_array,
        label_array,
        test_size=0.2,
        random_state=42,
        stratify=label_array,
    )

    model = build_model(input_shape=(sequence_array.shape[1], sequence_array.shape[2]))

    callbacks = [
        keras.callbacks.EarlyStopping(
            monitor="val_loss",
            patience=5,
            restore_best_weights=True,
        )
    ]

    model.fit(
        X_train,
        y_train,
        validation_split=0.2,
        epochs=30,
        batch_size=8,
        callbacks=callbacks,
        verbose=1,
    )

    loss, accuracy = model.evaluate(X_test, y_test, verbose=0)
    print(f"Test loss: {loss:.4f}")
    print(f"Test accuracy: {accuracy:.4f}")

    model.save(MODEL_OUT)
    print(f"Saved LSTM model to {MODEL_OUT}")

    scaler = MinMaxScaler()
    X_train_reshaped = X_train.reshape(-1, X_train.shape[-1])
    scaler.fit(X_train_reshaped)
    joblib.dump(scaler, SCALER_OUT)
    print(f"Saved LSTM scaler to {SCALER_OUT}")
    return model


if __name__ == "__main__":
    raw_df = load_raw_data(RAW_CSV)
    print(f"Loaded {len(raw_df)} raw rows from {RAW_CSV}")
    print(f"Using feature columns: {FEATURE_COLUMNS}")
    print(f"Building sequences with length {SEQUENCE_LENGTH}")

    sequence_array, label_array = build_sequences(raw_df, SEQUENCE_LENGTH)
    print(f"Built {len(sequence_array)} sequences")
    print(f"Label distribution: {dict(pd.Series(label_array).value_counts().sort_index())}")

    train_and_save(sequence_array, label_array)