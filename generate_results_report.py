"""
generate_results_report.py
==========================

Loads the labeled flow dataset and trained Random Forest model, scores every
flow, and writes a plain-text intrusion report to nids_results.txt while also
printing the same report to stdout.
"""

from pathlib import Path

import joblib
import pandas as pd


LABELED_FLOW_CSV = "labeled_flow_data.csv"
MODEL_FILE = "rf_flow_classifier.joblib"
OUTPUT_REPORT = "nids_results.txt"

FEATURE_COLUMNS = [
    "packet_count",
    "byte_count",
    "flow_duration",
    "packet_rate",
    "byte_rate",
    "avg_packet_size",
    "syn_ratio",
    "ack_ratio",
    "event_count",
]


def load_inputs(csv_path, model_path):
    flow_df = pd.read_csv(csv_path)
    model = joblib.load(model_path)
    return flow_df, model


def normalize_feature_names(flow_df, model):
    normalized_df = flow_df.copy()

    if "avg_packet_size" not in normalized_df.columns and "average_packet_size" in normalized_df.columns:
        normalized_df["avg_packet_size"] = normalized_df["average_packet_size"]

    if "average_packet_size" not in normalized_df.columns and "avg_packet_size" in normalized_df.columns:
        normalized_df["average_packet_size"] = normalized_df["avg_packet_size"]

    model_features = list(getattr(model, "feature_names_in_", FEATURE_COLUMNS))

    if "avg_packet_size" in model_features and "avg_packet_size" not in normalized_df.columns:
        raise ValueError("The model expects avg_packet_size but the input data does not provide it.")

    if "average_packet_size" in model_features and "average_packet_size" not in normalized_df.columns:
        raise ValueError("The model expects average_packet_size but the input data does not provide it.")

    return normalized_df, model_features


def score_flows(flow_df, model):
    flow_df, model_features = normalize_feature_names(flow_df, model)
    missing_columns = [column for column in model_features if column not in flow_df.columns]
    if missing_columns:
        raise ValueError(f"Missing required feature columns: {missing_columns}")

    feature_frame = flow_df[model_features]
    predicted_labels = model.predict(feature_frame)

    if not hasattr(model, "predict_proba"):
        raise AttributeError("Loaded model does not expose predict_proba().")

    probabilities = model.predict_proba(feature_frame)
    classes = list(getattr(model, "classes_", []))
    if 1 not in classes:
        raise ValueError("The trained model does not expose class 1 in classes_.")

    positive_class_index = classes.index(1)
    threat_scores = probabilities[:, positive_class_index]

    scored_df = flow_df.copy()
    scored_df["predicted_label"] = predicted_labels.astype(int)
    scored_df["threat_score"] = threat_scores.astype(float)
    return scored_df.sort_values("threat_score", ascending=False).reset_index(drop=True)


def build_report(scored_df):
    intrusion_df = scored_df[scored_df["predicted_label"] == 1]
    clear_df = scored_df[scored_df["predicted_label"] == 0]

    lines = []
    lines.append("NIDS RESULTS REPORT")
    lines.append("=" * 80)
    lines.append(f"Total flows: {len(scored_df)}")
    lines.append(f"Flagged intrusion: {len(intrusion_df)}")
    lines.append(f"Flagged clear: {len(clear_df)}")
    lines.append("")

    lines.append("INTRUSIONS DETECTED")
    lines.append("-" * 80)
    if intrusion_df.empty:
        lines.append("None")
    else:
        for _, row in intrusion_df.iterrows():
            attack_suffix = f", attack_type={row['attack_type']}" if pd.notna(row.get("attack_type")) else ""
            lines.append(
                f"{row['source_ip']} -> {row['dest_ip']}, dest_port={row['dest_port']}, "
                f"threat_score={row['threat_score']:.3f}{attack_suffix}"
            )

    lines.append("")
    lines.append("CLEAR / NORMAL TRAFFIC")
    lines.append("-" * 80)
    if clear_df.empty:
        lines.append("None")
    else:
        for _, row in clear_df.iterrows():
            lines.append(
                f"{row['source_ip']} -> {row['dest_ip']}, dest_port={row['dest_port']}, "
                f"threat_score={row['threat_score']:.3f}"
            )

    lines.append("")
    return "\n".join(lines)


def main():
    csv_path = Path(LABELED_FLOW_CSV)
    model_path = Path(MODEL_FILE)
    output_path = Path(OUTPUT_REPORT)

    flow_df, model = load_inputs(csv_path, model_path)
    scored_df = score_flows(flow_df, model)
    report = build_report(scored_df)

    output_path.write_text(report, encoding="utf-8")
    print(report)
    print(f"Report written to {output_path}")


if __name__ == "__main__":
    main()