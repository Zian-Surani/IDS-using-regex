# ann_classifier.py
"""
ANN loader + preprocessing + explainable predictions for NSL-KDD.

Exports:
- load_model_and_processors() -> (bool, dict | None)
- predict_from_record(df_no_header, preprocessors) -> DataFrame(prob_attack, pred_attack)
- predict_with_explanations(df_no_header, preprocessors, top_k=5) -> dict:
    {
      "preds": DataFrame(prob_attack, pred_attack),
      "explanations": [ { "top_features": [(name, score), ...],
                          "summary": "...(plain english)...",
                          "feature_contrib": { name: score, ... } },
                        ... ]
    }

Assumptions:
- Model: model/ann_model.h5
- OHE: preprocessors/ohe.pkl (for protocol_type, service, flag)
- Scaler: preprocessors/scaler.pkl (for numeric features)
- df_no_header has the NSL-KDD columns in order; if it has 43 columns, we take first 41 as features.
"""

from __future__ import annotations
import os
import joblib
import numpy as np
import pandas as pd
from typing import List, Tuple, Dict, Any

from tensorflow.keras.models import load_model

MODEL_PATH = "model/ann_model.h5"
OHE_PATH = "preprocessors/ohe.pkl"
SCALER_PATH = "preprocessors/scaler.pkl"

# Column names for NSL-KDD (43 incl. label & difficulty)
ALL_COLS = [
    'duration','protocol_type','service','flag','src_bytes','dst_bytes','land','wrong_fragment','urgent','hot',
    'num_failed_logins','logged_in','num_compromised','root_shell','su_attempted','num_root','num_file_creations',
    'num_shells','num_access_files','num_outbound_cmds','is_host_login','is_guest_login','count','srv_count',
    'serror_rate','srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate',
    'srv_diff_host_rate','dst_host_count','dst_host_srv_count','dst_host_same_srv_rate','dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate','dst_host_serror_rate','dst_host_srv_serror_rate',
    'dst_host_rerror_rate','dst_host_srv_rerror_rate','label','difficulty'
]
FEATURE_COLS = ALL_COLS[:41]
CAT_COLS = ['protocol_type','service','flag']
CAT_IDX = [FEATURE_COLS.index(c) for c in CAT_COLS]
NUM_COLS = [c for c in FEATURE_COLS if c not in CAT_COLS]


def load_model_and_processors():
    ok = all(os.path.exists(p) for p in [MODEL_PATH, OHE_PATH, SCALER_PATH])
    if not ok:
        return False, None
    model = load_model(MODEL_PATH)
    ohe = joblib.load(OHE_PATH)
    scaler = joblib.load(SCALER_PATH)
    return True, {"model": model, "ohe": ohe, "scaler": scaler}


def _ensure_features_df(df_no_header: pd.DataFrame) -> pd.DataFrame:
    """Take a user uploaded/pasted frame (no header) and coerce to 41 feature columns in NSL-KDD order."""
    n = df_no_header.shape[1]
    if n >= 41:
        X = df_no_header.iloc[:, :41].copy()
    else:
        # If fewer columns, pad with zeros (rare in practice).
        pad = pd.DataFrame(np.zeros((df_no_header.shape[0], 41 - n)))
        X = pd.concat([df_no_header.copy(), pad], axis=1)
    X.columns = FEATURE_COLS
    return X


def _feature_names_from_ohe(ohe) -> List[str]:
    """Return human-readable feature names for the one-hot columns."""
    names = []
    cats = ohe.categories_
    # protocol_type, service, flag (same order as fit)
    names += [f"protocol_type={v}" for v in cats[0]]
    names += [f"service={v}" for v in cats[1]]
    names += [f"flag={v}" for v in cats[2]]
    return names


def _preprocess(X: pd.DataFrame, preprocessors) -> Tuple[np.ndarray, List[str]]:
    """Return processed matrix and combined feature names."""
    ohe = preprocessors["ohe"]
    scaler = preprocessors["scaler"]

    X_cat = ohe.transform(X[CAT_COLS])
    X_num = scaler.transform(X[NUM_COLS])
    X_proc = np.hstack([X_num, X_cat])

    feature_names = NUM_COLS + _feature_names_from_ohe(ohe)
    return X_proc, feature_names


def predict_from_record(df_no_header: pd.DataFrame, preprocessors) -> pd.DataFrame:
    """Basic prediction without explanations."""
    X = _ensure_features_df(df_no_header)
    X_proc, _ = _preprocess(X, preprocessors)
    model = preprocessors["model"]
    probs = model.predict(X_proc, verbose=0).ravel()
    preds = (probs >= 0.5).astype(int)
    return pd.DataFrame({"prob_attack": probs, "pred_attack": preds})


# ---------------- Explanations ----------------

def _approx_feature_strengths(model) -> np.ndarray:
    """
    Heuristic per-feature strength using first Dense layer weights combined with downstream layers.
    This is a light, fast surrogate—not a formal attribution method like SHAP/IG.
    """
    weights = model.get_weights()
    # Expect: W1 (in->h1), b1, W2 (h1->h2), b2, W3 (h2->out), b3
    if len(weights) < 6:
        # fallback: just |W1|
        W1 = weights[0]
        return np.sum(np.abs(W1), axis=1)

    W1 = weights[0]           # (in_dim, h1)
    W2 = weights[2]           # (h1, h2)
    W3 = weights[4]           # (h2, 1)

    # collapse downstream magnitude per hidden unit to output
    # hidden_importance[j] ~ sum_k |W2[j,k]*W3[k,0]|
    hidden_importance = np.sum(np.abs(W2 * W3.T), axis=1)  # (h1,)
    # feature_strength[i] ~ sum_j |W1[i,j]| * hidden_importance[j]
    feat_strength = np.sum(np.abs(W1) * hidden_importance[None, :], axis=1)  # (in_dim,)
    return feat_strength


def _feature_explanations_map() -> Dict[str, str]:
    """Layman descriptions for typical NSL-KDD features and one-hots."""
    desc = {
        # Numerics (a few common ones—extend as needed)
        "duration": "How long the connection lasted.",
        "src_bytes": "Bytes sent from source to destination.",
        "dst_bytes": "Bytes sent from destination to source.",
        "count": "Connections to the same host in the last window.",
        "srv_count": "Connections to the same service in the last window.",
        "serror_rate": "Share of SYN or connection errors (possible scan/DoS).",
        "rerror_rate": "Share of connection resets (possible probe/failure).",
        "same_srv_rate": "How often the same service is contacted.",
        "diff_srv_rate": "How often different services are contacted.",
        "srv_diff_host_rate": "How often the service is on a different host.",
        "dst_host_count": "Connections to the same destination host.",
        "dst_host_srv_count": "Connections to the same dest host and service.",
        "dst_host_serror_rate": "Dest host SYN/connection errors.",
        "dst_host_rerror_rate": "Dest host reset errors.",
        # One-hot prefixes
        "protocol_type=": "Network protocol used.",
        "service=": "Application service targeted.",
        "flag=": "Connection status/flag returned by the server."
    }
    return desc


def _summarize_row(top_features: List[Tuple[str, float]], prob: float) -> str:
    """Plain-English one-liner explaining why it looks normal/attacky."""
    cues = [name for name, _ in top_features[:3]]
    if prob >= 0.8:
        return f"High likelihood of attack (p={prob:.2f}) driven by: " + ", ".join(cues) + "."
    if prob >= 0.5:
        return f"Moderate likelihood of attack (p={prob:.2f}) influenced by: " + ", ".join(cues) + "."
    return f"Likely normal (p={prob:.2f}). Most influential features: " + ", ".join(cues) + "."


def predict_with_explanations(
    df_no_header: pd.DataFrame,
    preprocessors: Dict[str, Any],
    top_k: int = 5
) -> Dict[str, Any]:
    """
    Return predictions and simple, layman-friendly explanations per row.
    """
    X = _ensure_features_df(df_no_header)
    X_proc, feature_names = _preprocess(X, preprocessors)
    model = preprocessors["model"]

    # predictions
    probs = model.predict(X_proc, verbose=0).ravel()
    preds = (probs >= 0.5).astype(int)
    preds_df = pd.DataFrame({"prob_attack": probs, "pred_attack": preds})

    # approximate per-feature strengths (global) and scale by each row's feature magnitude
    strengths = _approx_feature_strengths(model)  # (n_features,)
    eps = 1e-9
    explanations = []
    name_map = _feature_explanations_map()

    # Build readable descriptions map for one-hots too
    def describe_feature(fname: str) -> str:
        for prefix, text in [("protocol_type=", name_map["protocol_type="]),
                             ("service=", name_map["service="]),
                             ("flag=", name_map["flag="])]:
            if fname.startswith(prefix):
                return f"{text} ({fname.split('=',1)[1]})"
        # numeric fallback
        return name_map.get(fname, "Model feature")

    for i in range(X_proc.shape[0]):
        x = X_proc[i, :]
        # influence_i = |x_i| * strength_i
        influence = np.abs(x) * strengths
        # normalize for display
        total = float(np.sum(influence) + eps)
        contrib = influence / total
        # top-k
        idx = np.argsort(contrib)[::-1][:top_k]
        top_feats = [(feature_names[j], float(contrib[j])) for j in idx]
        # summary
        summary = _summarize_row(top_feats, float(probs[i]))
        # Make a readable dict with descriptions
        expl_rows = []
        for name, score in top_feats:
            expl_rows.append((name, score, describe_feature(name)))

        explanations.append({
            "top_features": expl_rows,            # (name, normalized_score, description)
            "summary": summary,
            "feature_contrib": {name: float(contrib[j]) for j, name in zip(idx, [feature_names[k] for k in idx])}
        })

    return {"preds": preds_df, "explanations": explanations}
