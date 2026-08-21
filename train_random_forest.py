"""
train_random_forest.py
=========================
STAGE 1 of the pipeline (LSTM dataset pipeline comes after this).

Takes the raw mock_nids_traffic.csv (one row per observed connection/event)
and does three things, in order:

  1. Groups rows into FLOWS using the same stable flow_key concept from
     trafficAnalyzer.py: (source_ip, dest_ip, dest_port, protocol).
  2. Aggregates each flow's rows into ONE summary row of RF-ready features
     and exports it as labeled_flow_data.csv -- this file is the reusable
     "labeled flow data" artifact your LSTM pipeline and future retraining
     runs can both build on.
  3. Trains the Random Forest on that flow-level table and saves the model.

Run: python train_random_forest.py
Outputs: labeled_flow_data.csv, rf_flow_classifier.joblib
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib

RAW_CSV = "mock_nids_traffic.csv"
FLOW_CSV_OUT = "labeled_flow_data.csv"
MODEL_OUT = "rf_flow_classifier.joblib"

RF_FEATURE_COLUMNS = [
    "packet_count", "byte_count", "flow_duration", "packet_rate",
    "byte_rate", "average_packet_size", "syn_ratio", "ack_ratio",
    "event_count",
]


# ------------------------------------------------------------------ #
# STEP 1: Load raw rows and assign a stable flow_key to each
# ------------------------------------------------------------------ #
def load_and_key(path):
    df = pd.read_csv(path, parse_dates=["timestamp"])

    # Same idea as get_flow_key() in trafficAnalyzer.py: group by the
    # 4-tuple that identifies a conversation. (Direction canonicalization
    # is skipped here since this mock data only records one direction
    # per row -- source_ip is always the initiator.)
    df["flow_key"] = list(zip(
        df["source_ip"], df["dest_ip"], df["dest_port"], df["protocol"]
    ))
    return df


# ------------------------------------------------------------------ #
# STEP 2: Aggregate each flow's rows into ONE RF feature row
# ------------------------------------------------------------------ #
def aggregate_flows(df):
    flow_rows = []

    for flow_key, group in df.groupby("flow_key"):
        group = group.sort_values("timestamp")

        event_count = len(group)                      # how many rows/events this flow had
        packet_count = int(group["packet_count"].sum())
        byte_count = int(group["byte_count"].sum())

        start_time = group["timestamp"].iloc[0]
        end_time = group["timestamp"].iloc[-1]
        # if a flow is a single row, fall back to that row's own duration
        # instead of a zero timestamp-span, so packet_rate stays meaningful.
        span = (end_time - start_time).total_seconds()
        flow_duration = span if span > 0 else float(group["duration"].sum())
        safe_duration = flow_duration if flow_duration > 0 else 1e-6

        syn_ratio = float(group["flag_syn"].mean())
        ack_ratio = float(group["flag_ack"].mean())
        average_packet_size = byte_count / packet_count if packet_count > 0 else 0.0

        # A flow is labeled an attack if ANY row in it was flagged as an
        # attack. attack_type takes the first non-Normal type seen, so you
        # can still audit which pattern drove the label.
        label = int(group["label"].max())
        non_normal = group.loc[group["attack_type"] != "Normal", "attack_type"]
        attack_type = non_normal.iloc[0] if len(non_normal) else "Normal"

        flow_rows.append({
            "source_ip": flow_key[0],
            "dest_ip": flow_key[1],
            "dest_port": flow_key[2],
            "protocol": flow_key[3],
            "event_count": event_count,
            "packet_count": packet_count,
            "byte_count": byte_count,
            "flow_duration": flow_duration,
            "packet_rate": packet_count / safe_duration,
            "byte_rate": byte_count / safe_duration,
            "average_packet_size": average_packet_size,
            "syn_ratio": syn_ratio,
            "ack_ratio": ack_ratio,
            "label": label,
            "attack_type": attack_type,
        })

    return pd.DataFrame(flow_rows)


# ------------------------------------------------------------------ #
# STEP 3: Export the labeled flow table, then train + save the RF
# ------------------------------------------------------------------ #
def train_and_save(flow_df):
    X = flow_df[RF_FEATURE_COLUMNS]
    y = flow_df["label"]

    # NOTE: this mock dataset only has ~20 flows after aggregation (most
    # attack rows collapse into a handful of flows: one DDoS flow, one
    # brute-force flow, one port-scan flow, plus 15 normal flows). That's
    # too few for a real held-out test split to mean anything -- so here
    # we skip test_size logic when the dataset is this small and just
    # report training-set performance as a sanity check, not a real
    # evaluation. Once you have thousands of real flows, switch back to
    # the train_test_split approach from 01_random_forest_basics.py.
    if len(flow_df) < 30:
        print(f"NOTE: only {len(flow_df)} flows after aggregation -- "
              f"too small for a meaningful train/test split. Training on "
              f"all of it and reporting in-sample fit as a sanity check only.\n")
        X_train, y_train = X, y
        X_test, y_test = X, y
    else:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=8,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    class_counts = y.value_counts().to_dict()
    print("Class distribution:")
    print(class_counts)

    y_pred = clf.predict(X_test)
    print("Confusion matrix:")
    print(confusion_matrix(y_test, y_pred))
    print("\nClassification report:")
    print(classification_report(y_test, y_pred, target_names=["normal", "attack"]))

    importances = pd.Series(clf.feature_importances_, index=RF_FEATURE_COLUMNS)
    print("Feature importances:")
    print(importances.sort_values(ascending=False))

    joblib.dump(clf, MODEL_OUT)
    print(f"\nSaved model to {MODEL_OUT}")
    return clf


if __name__ == "__main__":
    raw_df = load_and_key(RAW_CSV)
    print(f"Loaded {len(raw_df)} raw rows from {RAW_CSV}")

    flow_df = aggregate_flows(raw_df)
    print(f"Aggregated into {len(flow_df)} flows\n")
    print(flow_df[["source_ip", "dest_ip", "dest_port", "event_count",
                    "packet_count", "label", "attack_type"]].to_string(index=False))

    flow_df.to_csv(FLOW_CSV_OUT, index=False)
    print(f"\nExported labeled flow data to {FLOW_CSV_OUT}")

    print("\n" + "=" * 60 + "\nTraining Random Forest\n" + "=" * 60)
    train_and_save(flow_df)
