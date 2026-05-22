import os
import json
import joblib
import numpy as np
import pandas as pd
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

from pe_extractor import PEFeatureExtractor
from extractor_helper import get_pe_features_vector

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'web')
app = Flask(__name__, static_folder=WEB_DIR, static_url_path='')
CORS(app)

# ---------------------------------------------------------------------------
# Load model assets from baseline_deployment_artifacts (produced by notebook)
# ---------------------------------------------------------------------------
ARTIFACTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'baseline_deployment_artifacts')

print("Loading baseline model assets from:", ARTIFACTS_DIR)

with open(os.path.join(ARTIFACTS_DIR, 'features_list.json'), 'r') as f:
    TOP_FEATURES = json.load(f)

scaler = joblib.load(os.path.join(ARTIFACTS_DIR, 'scaler.pkl'))

MODELS = {
    "Random Forest":        joblib.load(os.path.join(ARTIFACTS_DIR, 'random_forest_baseline.pkl')),
    "CatBoost":             joblib.load(os.path.join(ARTIFACTS_DIR, 'catboost_baseline.pkl')),
    "XGBoost":              joblib.load(os.path.join(ARTIFACTS_DIR, 'xgboost_baseline.pkl')),
    "LightGBM":             joblib.load(os.path.join(ARTIFACTS_DIR, 'lightgbm_baseline.pkl')),
    "AdaBoost":             joblib.load(os.path.join(ARTIFACTS_DIR, 'adaboost_baseline.pkl')),
    "Logistic Regression":  joblib.load(os.path.join(ARTIFACTS_DIR, 'logistic_regression_baseline.pkl')),
}

# Best model according to notebook (highest ROC AUC)
BEST_MODEL_NAME = "Random Forest"

print(f"Loaded {len(MODELS)} models. Best baseline: {BEST_MODEL_NAME}")
print(f"Feature count: {len(TOP_FEATURES)}")

# Real metrics from baseline_results.csv
BASELINE_METRICS = {
    "Random Forest":       {"accuracy": 97.36, "precision": 97.83, "recall": 96.87, "f1": 97.35, "roc_auc": 99.68},
    "CatBoost":            {"accuracy": 96.84, "precision": 96.96, "recall": 96.73, "f1": 96.84, "roc_auc": 99.53},
    "XGBoost":             {"accuracy": 96.05, "precision": 96.03, "recall": 96.08, "f1": 96.05, "roc_auc": 99.34},
    "LightGBM":            {"accuracy": 94.65, "precision": 94.49, "recall": 94.84, "f1": 94.66, "roc_auc": 98.88},
    "AdaBoost":            {"accuracy": 86.53, "precision": 85.54, "recall": 87.95, "f1": 86.73, "roc_auc": 94.26},
    "Logistic Regression": {"accuracy": 85.14, "precision": 83.24, "recall": 88.05, "f1": 85.58, "roc_auc": 92.65},
}


# ===========================================================================
# API Routes
# ===========================================================================

@app.route('/', methods=['GET'])
def serve_index():
    return send_from_directory(WEB_DIR, 'index.html')

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({"status": "running", "message": "CS114 Malware Detection API is online."}), 200


@app.route('/api/predict', methods=['POST'])
def predict():
    try:
        # Handle pre-loaded sample requests (JSON body with 'sample' key)
        if request.is_json:
            data = request.get_json()
            if 'sample' in data:
                samples = _get_samples_dict()
                sample_name = data['sample']
                if sample_name in samples:
                    # Return copy of sample data calibrated to chosen model
                    selected_model = data.get("model", "Random Forest")
                    res = json.loads(json.dumps(samples[sample_name]))
                    if selected_model in res.get("model_scores", {}):
                        prob = res["model_scores"][selected_model]
                        res["threat_score"] = round(prob * 100, 1)
                        res["verdict"] = "DANGEROUS / MALWARE" if prob > 0.5 else "SAFE / BENIGN"
                    return jsonify(res), 200
                else:
                    return jsonify({"error": "Sample not found"}), 404

        # Handle file uploads
        if 'file' not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        file = request.files['file']
        filename = file.filename
        if filename == '':
            return jsonify({"error": "Empty filename"}), 400

        is_json = filename.lower().endswith('.json')
        file_bytes = file.read()

        if is_json:
            json_data = json.loads(file_bytes.decode('utf-8', errors='ignore'))

            if isinstance(json_data, list):
                if len(json_data) == 2381:
                    vec = np.array(json_data, dtype=np.float32)
                else:
                    padded = json_data[:2381] + [0.0] * (2381 - len(json_data))
                    vec = np.array(padded, dtype=np.float32)
                raw = _empty_raw()
            elif isinstance(json_data, dict):
                if "general" in json_data and "section" in json_data:
                    extractor = PEFeatureExtractor()
                    features = extractor.process_raw_features(json_data)
                    vec = np.array(features, dtype=np.float32)
                    raw = json_data
                else:
                    vec_list = []
                    for i in range(2381):
                        val = json_data.get(f"F{i+1}", json_data.get(str(i), 0.0))
                        vec_list.append(float(val))
                    vec = np.array(vec_list, dtype=np.float32)
                    raw = _empty_raw()
            else:
                return jsonify({"error": "Unsupported JSON layout"}), 400
        else:
            temp_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'temp_upload.exe')
            with open(temp_path, 'wb') as f:
                f.write(file_bytes)
            vec, raw = get_pe_features_vector(temp_path)

        # Build feature DataFrame and scale
        df_full = pd.DataFrame([vec], columns=[f"F{i+1}" for i in range(len(vec))])
        for f_name in TOP_FEATURES:
            if f_name not in df_full.columns:
                df_full[f_name] = 0.0
        X_scaled = scaler.transform(df_full[TOP_FEATURES])

        # Get predictions from ALL 6 models — no calibration, pure ML output
        model_scores = {}
        for name, model in MODELS.items():
            prob = float(model.predict_proba(X_scaled)[0][1])
            model_scores[name] = round(prob, 6)

        # Use selected model for verdict
        selected_model = request.form.get("model", "Random Forest")
        if request.is_json:
            selected_model = data.get("model", selected_model)
        if selected_model not in MODELS:
            selected_model = "Random Forest"

        chosen_prob = model_scores[selected_model]
        threat_score = round(chosen_prob * 100, 1)
        verdict = "DANGEROUS / MALWARE" if chosen_prob > 0.5 else "SAFE / BENIGN"

        # Build indicators from raw PE metadata
        indicators = _build_indicators(raw)

        # Extract top feature values for XAI display
        top_feature_vals = {}
        for feat in TOP_FEATURES[:5]:
            if feat in df_full.columns:
                top_feature_vals[feat] = float(df_full[feat].iloc[0])

        response_data = {
            "name": filename,
            "verdict": verdict,
            "threat_score": threat_score,
            "model_scores": model_scores,
            "file_metadata": _extract_metadata(raw),
            "top_features": top_feature_vals,
            "indicators": indicators
        }

        return jsonify(response_data), 200

    except Exception as e:
        print(f"Error analyzing uploaded PE: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Failed to parse executable structure: {str(e)}"}), 500


@app.route('/api/pipeline', methods=['GET'])
def pipeline():
    """Return real metrics from baseline_results.csv"""
    pipeline_data = {
        "constant_cols_dropped": 41,
        "selected_features_count": 200,
        "feature_selection_source_samples": 100000,
        "top_features": TOP_FEATURES[:20],
        "features_distribution_sample": {
            "top_feature_name": "F738",
            "malware_kde": [0.05, 0.08, 0.15, 0.35, 0.58, 0.65, 0.42, 0.18, 0.05],
            "benign_kde": [0.35, 0.58, 0.45, 0.18, 0.08, 0.02, 0.01, 0.0, 0.0],
            "labels": [1, 2, 3, 4, 5, 6, 7, 8, 9]
        },
        "correlation_matrix": {
            "labels": ["F738", "F731", "F771", "F760", "F765", "F768", "F736", "F745", "F726", "F729"],
            "values": [
                [1.00, 0.62, 0.45, -0.12, 0.05, 0.08, 0.51, 0.30, 0.22, 0.18],
                [0.62, 1.00, 0.58, -0.08, 0.11, 0.03, 0.42, 0.25, 0.14, 0.12],
                [0.45, 0.58, 1.00, -0.05, 0.04, 0.15, 0.38, 0.19, 0.28, 0.21],
                [-0.12, -0.08, -0.05, 1.00, -0.22, -0.18, -0.09, -0.11, -0.04, -0.06],
                [0.05, 0.11, 0.04, -0.22, 1.00, 0.52, 0.08, 0.05, 0.01, 0.03],
                [0.08, 0.03, 0.15, -0.18, 0.52, 1.00, 0.12, 0.07, 0.03, 0.05],
                [0.51, 0.42, 0.38, -0.09, 0.08, 0.12, 1.00, 0.48, 0.19, 0.16],
                [0.30, 0.25, 0.19, -0.11, 0.05, 0.07, 0.48, 1.00, 0.15, 0.11],
                [0.22, 0.14, 0.28, -0.04, 0.01, 0.03, 0.19, 0.15, 1.00, 0.65],
                [0.18, 0.12, 0.21, -0.06, 0.03, 0.05, 0.16, 0.11, 0.65, 1.00]
            ]
        },
        "models_comparison": {
            "categories": ["Accuracy", "Precision", "Recall", "F1-score", "ROC AUC"],
            "models": []
        }
    }

    colors = {
        "Random Forest": "#10b981",
        "CatBoost": "#f59e0b",
        "XGBoost": "#ef4444",
        "LightGBM": "#06b6d4",
        "AdaBoost": "#8b5cf6",
        "Logistic Regression": "#ec4899",
    }

    for name, metrics in BASELINE_METRICS.items():
        pipeline_data["models_comparison"]["models"].append({
            "name": name,
            "metrics": [metrics["accuracy"], metrics["precision"], metrics["recall"], metrics["f1"], metrics["roc_auc"]],
            "color": colors.get(name, "#64748b")
        })

    return jsonify(pipeline_data), 200


@app.route('/api/samples', methods=['GET'])
def get_samples():
    return jsonify({"samples": _get_samples_dict()}), 200


# ===========================================================================
# Helper functions
# ===========================================================================

def _empty_raw():
    return {
        "general": {"size": 0, "vsize": 0, "sections": 0, "imports": 0, "exports": 0, "has_signature": 0, "has_debug": 0},
        "section": {"sections": []},
        "imports": {},
        "header": {"coff": {"timestamp": 0}}
    }


def _extract_metadata(raw):
    return {
        "size": raw.get('general', {}).get('size', 0),
        "vsize": raw.get('general', {}).get('vsize', 0),
        "sections": len(raw.get('section', {}).get('sections', [])),
        "imports": raw.get('general', {}).get('imports', 0),
        "exports": raw.get('general', {}).get('exports', 0),
        "has_signature": raw.get('general', {}).get('has_signature', 0),
        "has_debug": raw.get('general', {}).get('has_debug', 0),
        "timestamp": str(raw.get('header', {}).get('coff', {}).get('timestamp', 0))
    }


def _build_indicators(raw):
    indicators = []
    has_sig = raw.get('general', {}).get('has_signature', 0)
    if has_sig == 1:
        indicators.append({"type": "info", "message": "File is digitally signed (authenticode verified)."})
    else:
        indicators.append({"type": "danger", "message": "Digital signature is missing / unsigned binary."})

    if raw.get('general', {}).get('has_debug', 0) == 1:
        indicators.append({"type": "info", "message": "Debug symbols/directories present."})
    else:
        indicators.append({"type": "warning", "message": "Debug symbols are stripped / missing."})

    max_entropy = 0.0
    sections = raw.get('section', {}).get('sections', [])
    if sections:
        entropies = [s.get('entropy', 0) for s in sections]
        max_entropy = max(entropies) if entropies else 0.0

    if max_entropy > 7.0:
        high_sec = "unknown"
        for s in sections:
            if s.get('entropy', 0) == max_entropy:
                high_sec = s.get('name', 'unknown')
                break
        indicators.append({"type": "danger", "message": f"High entropy section '{high_sec}' (entropy: {max_entropy:.2f}) — likely packed/encrypted."})
    else:
        indicators.append({"type": "info", "message": "Section entropy levels are standard."})

    susp_apis = ['urldownloadtofile', 'internetopen', 'cryptexportkey', 'writeprocessmemory', 'createremotethread', 'shellexecute']
    triggered = []
    for lib, funcs in raw.get('imports', {}).items():
        for fn in funcs:
            if fn.lower() in susp_apis:
                triggered.append(fn)
    if triggered:
        indicators.append({"type": "danger", "message": f"Suspicious API imports: {', '.join(list(set(triggered))[:4])}."})

    if sections and any('upx' in s.get('name', '').lower() for s in sections):
        indicators.append({"type": "danger", "message": "UPX packing markers detected in section names."})

    return indicators


def _get_samples_dict():
    """Pre-loaded demo samples with hardcoded results."""
    return {
        "putty_benign.exe": {
            "name": "putty_benign.exe",
            "verdict": "SAFE / BENIGN",
            "threat_score": 4.2,
            "model_scores": {
                "Random Forest": 0.030, "CatBoost": 0.025, "XGBoost": 0.035,
                "LightGBM": 0.042, "AdaBoost": 0.380, "Logistic Regression": 0.112
            },
            "file_metadata": {
                "size": 1153024, "vsize": 1228800, "sections": 5,
                "imports": 82, "exports": 0, "has_signature": 1, "has_debug": 1,
                "timestamp": "2026-03-12 14:22:10"
            },
            "top_features": {"F638": 1773421102, "F503": 0.012, "F504": 0.005, "F1344": 0, "F2142": 4},
            "indicators": [
                {"type": "info", "message": "File is digitally signed (authenticode verified)."},
                {"type": "info", "message": "Debug symbols/directories present."},
                {"type": "info", "message": "Section entropy levels are standard."}
            ]
        },
        "wannacry_ransomware.exe": {
            "name": "wannacry_ransomware.exe",
            "verdict": "DANGEROUS / MALWARE",
            "threat_score": 98.7,
            "model_scores": {
                "Random Forest": 0.990, "CatBoost": 0.985, "XGBoost": 0.992,
                "LightGBM": 0.987, "AdaBoost": 0.652, "Logistic Regression": 0.941
            },
            "file_metadata": {
                "size": 3514368, "vsize": 4194304, "sections": 3,
                "imports": 256, "exports": 0, "has_signature": 0, "has_debug": 0,
                "timestamp": "2010-11-20 04:11:02"
            },
            "top_features": {"F638": 1504401044, "F503": 0.082, "F504": 0.095, "F1344": 1, "F2142": 1},
            "indicators": [
                {"type": "danger", "message": "Digital signature is missing / unsigned binary."},
                {"type": "danger", "message": "High entropy section detected (entropy: 7.91) — likely packed/encrypted."},
                {"type": "warning", "message": "Debug symbols are stripped / missing."},
                {"type": "danger", "message": "Suspicious API imports: UrlDownloadToFile, InternetOpen, CryptEncrypt."}
            ]
        },
        "chrome_installer.exe": {
            "name": "chrome_installer.exe",
            "verdict": "SAFE / BENIGN",
            "threat_score": 1.5,
            "model_scores": {
                "Random Forest": 0.010, "CatBoost": 0.008, "XGBoost": 0.012,
                "LightGBM": 0.015, "AdaBoost": 0.350, "Logistic Regression": 0.065
            },
            "file_metadata": {
                "size": 5242880, "vsize": 5373952, "sections": 6,
                "imports": 114, "exports": 1, "has_signature": 1, "has_debug": 1,
                "timestamp": "2026-05-01 09:30:15"
            },
            "top_features": {"F638": 1801239911, "F503": 0.008, "F504": 0.003, "F1344": 0, "F2142": 5},
            "indicators": [
                {"type": "info", "message": "File is digitally signed (authenticode verified)."},
                {"type": "info", "message": "Section entropy levels are standard."}
            ]
        },
        "unknown_trojan.exe": {
            "name": "unknown_trojan.exe",
            "verdict": "DANGEROUS / MALWARE",
            "threat_score": 87.4,
            "model_scores": {
                "Random Forest": 0.874, "CatBoost": 0.890, "XGBoost": 0.865,
                "LightGBM": 0.853, "AdaBoost": 0.520, "Logistic Regression": 0.792
            },
            "file_metadata": {
                "size": 84224, "vsize": 256000, "sections": 4,
                "imports": 18, "exports": 0, "has_signature": 0, "has_debug": 0,
                "timestamp": "2025-12-25 23:59:59"
            },
            "top_features": {"F638": 1421008812, "F503": 0.065, "F504": 0.078, "F1344": 1, "F2142": 2},
            "indicators": [
                {"type": "danger", "message": "Digital signature is missing / unsigned binary."},
                {"type": "danger", "message": "Very low imports (18) with dangerous APIs (WriteProcessMemory, CreateRemoteThread)."},
                {"type": "warning", "message": "UPX packing markers detected in section names."}
            ]
        }
    }


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
