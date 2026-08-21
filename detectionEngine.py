from pathlib import Path

import joblib
import pandas as pd
import numpy as np

class DetectionEngine:
    FUSION_WEIGHTS = {
        'random_forest': 0.6,
        'lstm': 0.4,
    }

    RF_FEATURE_ORDER = [
        'packet_count',
        'byte_count',
        'flow_duration',
        'packet_rate',
        'byte_rate',
        'average_packet_size',
        'syn_ratio',
        'ack_ratio',
        'event_count'
    ]

    def __init__(self, model_dir="."):
        self.model_dir = Path(model_dir)
        self.signature_rules = self.load_signature_rules()
        self.random_forest_model = self._load_model(["rf_flow_classifier.joblib", "random_forest_ids.pkl"])
        self.lstm_model = self._load_keras_model(["lstm_ids.keras", "lstm_ids.h5"])

    def load_signature_rules(self):
        return {
            'syn_flood': {
                'condition': lambda features: (
                    features.get('tcp_flags', 0) == 2 and  #SYN flag
                    features.get('packet_rate', 0) > 100
                )
            },
            'port_scan': {
                'condition': lambda features: (
                    features.get('packet_size', 0) < 100 and 
                    features.get('packet_rate', 0) > 50
                )
            }
        }
    
    def _load_model(self, filenames):
        for filename in filenames:
            model_path = self.model_dir / filename
            if model_path.exists():
                return joblib.load(model_path)
        return None

    def _load_keras_model(self, filenames):
        try:
            from tensorflow import keras
        except ImportError:
            return None

        for filename in filenames:
            model_path = self.model_dir / filename
            if model_path.exists():
                return keras.models.load_model(model_path)
        return None

    def _build_random_forest_vector(self, flow_features):
        return pd.DataFrame([
            {name: flow_features.get(name, 0.0) for name in self.RF_FEATURE_ORDER}
        ], columns=self.RF_FEATURE_ORDER)

    def _positive_class_probability(self, model, feature_vector):
        if not hasattr(model, 'predict_proba'):
            return None

        probabilities = model.predict_proba(feature_vector)[0]
        classes = list(getattr(model, 'classes_', []))
        if 1 in classes:
            return float(probabilities[classes.index(1)])

        return float(probabilities[-1]) if len(probabilities) else None

    def _predict_random_forest(self, flow_features):
        if self.random_forest_model is None:
            return None

        feature_vector = self._build_random_forest_vector(flow_features)
        predicted_class = int(self.random_forest_model.predict(feature_vector)[0])
        predicted_probability = self._positive_class_probability(self.random_forest_model, feature_vector)
        if predicted_probability is None:
            predicted_probability = 1.0 if predicted_class == 1 else 0.0

        return {
            'type': 'random_forest',
            'prediction': predicted_class,
            'confidence': predicted_probability,
            'score': predicted_probability
        }

    def _predict_lstm(self, sequence):
        if self.lstm_model is None or not sequence:
            return None

        sequence_array = np.array([sequence], dtype=float)
        predicted_probability = float(self.lstm_model.predict(sequence_array, verbose=0)[0][0])

        return {
            'type': 'lstm',
            'prediction': 1 if predicted_probability >= 0.5 else 0,
            'confidence': predicted_probability,
            'score': predicted_probability
        }

    def _fuse_model_outputs(self, random_forest_threat, lstm_threat):
        model_outputs = []

        if random_forest_threat is not None:
            model_outputs.append(random_forest_threat)
        if lstm_threat is not None:
            model_outputs.append(lstm_threat)

        if not model_outputs:
            return None

        weighted_score = 0.0
        total_weight = 0.0

        for threat in model_outputs:
            weight = self.FUSION_WEIGHTS.get(threat['type'], 0.0)
            weighted_score += weight * float(threat.get('confidence', 0.0))
            total_weight += weight

        if total_weight == 0.0:
            return None

        fused_score = weighted_score / total_weight
        return {
            'type': 'fused',
            'source_models': [threat['type'] for threat in model_outputs],
            'rf_confidence': random_forest_threat.get('confidence') if random_forest_threat else None,
            'lstm_confidence': lstm_threat.get('confidence') if lstm_threat else None,
            'confidence': fused_score,
            'score': fused_score,
            'prediction': 1 if fused_score >= 0.5 else 0,
        }
    
    def detect_threats(self, analysis_result):
        threats = []
        flow_features = analysis_result.get('flow_features', {})
        sequence = analysis_result.get('sequence', [])

        # Signature-based detection
        for rule_name, rule in self.signature_rules.items():
            if flow_features and rule['condition'](flow_features):
                threats.append({
                    'type': 'signature',
                    'rule': rule_name,
                    'confidence': 1.0
                })

        random_forest_threat = self._predict_random_forest(flow_features)
        lstm_threat = self._predict_lstm(sequence)

        fused_threat = self._fuse_model_outputs(random_forest_threat, lstm_threat)
        if fused_threat and fused_threat['prediction'] == 1:
            threats.append(fused_threat)

        if random_forest_threat and random_forest_threat['prediction'] == 1 and fused_threat is None:
            threats.append(random_forest_threat)

        if lstm_threat and lstm_threat['prediction'] == 1 and fused_threat is None:
            threats.append(lstm_threat)

        return threats