# Network IDS

A lightweight Python-based Network Intrusion Detection System prototype that combines packet capture, flow-based feature extraction, and machine learning to detect suspicious TCP traffic patterns such as SYN floods, port scans, and other abnormal flow behaviors.

This project is designed as a learning and research-oriented IDS pipeline rather than a production-ready enterprise NIDS. It demonstrates how to:

- capture packets from a network interface
- aggregate traffic into flows
- extract statistical features
- apply signature rules and ML models for threat detection
- log alerts for suspicious activity

---

## Overview

The system is composed of a few core modules:

- `packetCapture.py` – captures packets using Scapy
- `trafficAnalyzer.py` – groups packets into flows and extracts features
- `detectionEngine.py` – applies rule-based and model-based detection
- `alertSystem.py` – writes security alerts to a log
- `intrusionDetectionSystem.py` – orchestrates the full live detection workflow

The project also includes training scripts and synthetic traffic generation tools to build and evaluate a flow-based intrusion detection model.

---

## Architecture

The detection pipeline follows this flow:

1. Packet capture reads live traffic from an interface.
2. Only TCP/IP packets are processed.
3. Packets are normalized into flow-level records.
4. Flow statistics are calculated (counts, durations, rates, SYN/ACK ratios, etc.).
5. The detection engine evaluates:
   - signature rules for obvious suspicious patterns
   - a Random Forest classifier trained on flow-level features
   - an LSTM model for sequence-based behavior analysis
6. Alarms are written to a log file using the alert system.

---

## Features

### Packet capture
- Uses `scapy.sniff()` for live packet monitoring
- Captures only packets that include both IP and TCP layers
- Implements a queue-based pipeline for thread-safe packet processing

### Flow analysis
- Tracks per-flow packet counts, byte counts, timing, and protocol flags
- Builds a sequence window for LSTM-style input
- Extracts features such as:
  - packet rate
  - byte rate
  - average packet size
  - flow duration
  - SYN/ACK ratios
  - TCP flag counts

### Detection engine
- Rule-based checks for suspicious patterns such as:
  - SYN flood detection
  - port scan detection
- Random Forest model for flow classification
- LSTM model for sequence-based attack detection
- Fuses model scores into a combined confidence value

### Alerting
- Stores alerts in a log file such as `ids.alerts.log`
- Includes timestamp, threat type, device IPs, and confidence score

---

## Project files

- `packetCapture.py` – live packet capture
- `trafficAnalyzer.py` – flow aggregation and feature extraction
- `detectionEngine.py` – threat detection logic and ML integration
- `alertSystem.py` – alert generation and logging
- `intrusionDetectionSystem.py` – main IDS loop
- `generate_mock_dataset.py` – creates a synthetic attack dataset
- `train_random_forest.py` – trains the Random Forest model
- `train_lstm.py` – trains the LSTM model
- `generate_results_report.py` – creates a plain-text report of detections
- `mock_nids_traffic.csv` – generated synthetic network traffic data
- `labeled_flow_data.csv` – aggregated flow-level labeled dataset
- `rf_flow_classifier.joblib` – saved Random Forest model
- `lstm_ids.keras` – saved LSTM model
- `requirements.txt` – Python dependency list

---

## Requirements

The project depends on:

- Python 3.x
- Scapy
- NumPy
- pandas
- scikit-learn
- TensorFlow
- joblib

Install dependencies with:

```bash
pip install -r requirements.txt
```

---

## Running the project

### 1. Generate synthetic traffic data

```bash
python generate_mock_dataset.py
```

### 2. Train the models

```bash
python train_random_forest.py
python train_lstm.py
```

### 3. Run the IDS

```bash
python intrusionDetectionSystem.py
```

This starts packet capture and monitors traffic continuously until interrupted.

### 4. Generate a report

```bash
auto-generated outputs after training
```

A report script is available for evaluating the model on the flow dataset:

```bash
python generate_results_report.py
```

---

## Notes on usage

This project is best used in a controlled environment or lab setup. It is intended to demonstrate IDS concepts such as:

- traffic feature engineering
- model-based anomaly detection
- log-based alert generation
- flow-based network monitoring

It is not a full-featured production-grade NIDS and does not currently include:

- full protocol coverage beyond TCP/IP
- enterprise alert correlation
- real-time dashboards
- packet filtering for high-volume deployments
- robust threat intelligence integration
- deployment in a production monitoring stack

---

## Limitations

This project should be viewed as a prototype or educational implementation. Some important limitations include:

- It focuses on TCP traffic only.
- It uses synthetic/mock data rather than real-world network captures.
- Detection logic is rule-based and heuristic, not a mature IDS engine.
- Model performance depends heavily on the quality and realism of training data.
- It does not implement network blocking, response automation, or incident triage workflows.

---

## Future improvements

Possible upgrades include:

- support for UDP, ICMP, and IPv6
- integration with real PCAP files for validation
- improved feature engineering and model evaluation
- IDS rule sets based on real attack signatures
- alert deduplication and severity classification
- dashboards and SIEM-style reporting
- deployment as a service with configuration files and monitoring

---

## Summary

This repository demonstrates a practical introduction to network intrusion detection using Python, Scapy, and machine learning. It is a useful teaching and prototyping project for understanding how flow analysis and alert generation can support intrusion detection workflows.

For a production security deployment, this would need significant enhancement in detection coverage, operational tooling, and real-world validation.
