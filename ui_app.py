# ui_app.py
import streamlit as st
import pandas as pd
import re
from datetime import datetime
from urllib.parse import unquote

from regex_dfa_matcher import (
    load_patterns,
    build_detectors,
    match_regex,
    match_dfa,
    match_both,
    explain_pattern,
)

from alert_logger import log_alert

# Optional ANN
try:
    from ann_classifier import load_model_and_processors, predict_from_record, predict_with_explanations
    ANN_AVAILABLE = True
except Exception:
    ANN_AVAILABLE = False

# Packet capture & mapping to ANN
try:
    from packet_sniffer import capture_packets
    from payload_extractor import extract_payload
    from live_features import packet_to_nsl_row
    CAPTURE_AVAILABLE = True
except Exception:
    CAPTURE_AVAILABLE = False


# ---------- Helpers ----------
def _highlight(txt: str, patterns) -> str:
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

def _decode_payload(s: str, rounds: int = 2) -> str:
    for _ in range(rounds):
        s = unquote(s)
    return s


# ---------- Page ----------
st.set_page_config(page_title="IDS Dashboard", layout="wide", initial_sidebar_state="expanded")
st.title("🛡️ IDS Dashboard — Regex • DFA • Live ANN")
st.caption("Signature-based detection with formal automata + optional ANN on live packets (demo).")

# ---------- Sidebar ----------
st.sidebar.header("Mode")
mode = st.sidebar.selectbox("Detection mode", ["Regex", "DFA", "Both", "Live Capture (Regex/DFA + ANN)"], index=2)

st.sidebar.header("Signatures")
sig_file = st.sidebar.text_input("Signatures file", value="signatures.txt")
use_advanced = st.sidebar.checkbox("Use advanced set (signatures_advanced.txt)", value=False)
if use_advanced:
    sig_file = "signatures_advanced.txt"

# Load and edit signatures
try:
    current_patterns = load_patterns(sig_file)
except Exception:
    current_patterns = []

with st.sidebar.expander("Edit current signatures"):
    txt = st.text_area("One pattern per line (# for comments)", value="\n".join(current_patterns), height=220)
    if st.button("Save signatures to file"):
        try:
            with open(sig_file, "w", encoding="utf-8") as f:
                f.write(txt.rstrip() + "\n")
            st.success(f"Saved to {sig_file}")
            current_patterns = [ln for ln in txt.splitlines() if ln.strip() and not ln.strip().startswith("#")]
        except Exception as e:
            st.error(f"Write failed: {e}")

upload = st.sidebar.file_uploader("Replace patterns from upload", type=["txt"])
if upload:
    try:
        new = upload.read().decode("utf-8")
        with open(sig_file, "w", encoding="utf-8") as f:
            f.write(new)
        st.sidebar.success(f"Replaced {sig_file} from upload")
        current_patterns = [ln.strip() for ln in new.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    except Exception as e:
        st.sidebar.error(f"Failed to load uploaded signatures: {e}")


# ---------- Text input mode ----------
if mode in ["Regex", "DFA", "Both"]:
    st.header("Input")
    payload = st.text_area(
        "Paste logs / HTTP / payload text:",
        height=220,
        placeholder="GET /?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1\ncmd.exe /c whoami\nSELECT * FROM users"
    )
    decode = st.checkbox("URL-decode before scanning", value=True)
    run = st.button("🚀 Run detection")

    if run:
        txt = payload or ""
        if decode:
            txt = _decode_payload(txt)

        with st.spinner("Building detectors..."):
            detectors = build_detectors(current_patterns)

        if mode == "Regex":
            regex_hits = match_regex(detectors, txt); dfa_hits = []; both_hits = []
        elif mode == "DFA":
            dfa_hits = match_dfa(detectors, txt); regex_hits = []; both_hits = []
        else:
            out = match_both(detectors, txt)
            regex_hits, dfa_hits, both_hits = out["regex"], out["dfa"], out["both"]

        st.header("Results")
        c1, c2, c3 = st.columns(3)
        c1.metric("Regex matches", len(regex_hits))
        c2.metric("DFA matches", len(dfa_hits))
        c3.metric("High-confidence (both)", len(both_hits))

        # Log findings
        if regex_hits: log_alert("Regex", mode, payload, regex_hits, severity="medium")
        if dfa_hits:   log_alert("DFA",   mode, payload, dfa_hits,   severity="high" if both_hits else "medium")

        st.markdown("### Regex matches")
        if regex_hits:
            for p in regex_hits:
                with st.expander(f"⚠️ {p}", expanded=False):
                    st.write(explain_pattern(p))
        else:
            st.success("✅ No regex matches.")

        st.markdown("### DFA matches (formal)")
        if dfa_hits:
            for p in dfa_hits:
                with st.expander(f"⚠️ {p}", expanded=False):
                    st.write(explain_pattern(p))
        else:
            st.success("✅ No DFA matches.")

        if mode == "Both":
            st.markdown("### High-confidence (matched by BOTH)")
            if both_hits:
                for p in both_hits:
                    st.error(f"🚨 {p} — very likely malicious.")
                log_alert("Both", mode, payload, both_hits, severity="critical")
            else:
                st.info("No intersection between Regex and DFA matches.")

        st.markdown("### Highlighted input (first 2000 chars)")
        st.markdown(_highlight((txt or "")[:2000], regex_hits + dfa_hits), unsafe_allow_html=True)

# ---------- Live capture mode ----------
else:
    st.header("📡 Live Capture (Regex/DFA + ANN)")
    if not CAPTURE_AVAILABLE:
        st.warning("Capture demo not available (scapy/mapping modules missing).")
    else:
        n = st.slider("Packets to capture (demo)", 1, 15, 5)
        ann_enable = st.checkbox("Classify with ANN (if available)", value=True)
        decode = st.checkbox("URL-decode payloads", value=True)
        if st.button("Start capture"):
            pkts = capture_packets(n)
            model_ready = False
            preprocessors = None
            if ANN_AVAILABLE and ann_enable:
                try:
                    model_ready, preprocessors = load_model_and_processors()
                except Exception:
                    model_ready = False

            rows = []
            for i, p in enumerate(pkts, start=1):
                payload = extract_payload(p)
                shown = _decode_payload(payload) if decode else payload
                st.write(f"### Packet #{i}")
                st.code(shown[:800])

                # Build detectors once for speed
                if i == 1:
                    detectors = build_detectors(current_patterns)

                regex_hits = match_regex(detectors, shown)
                dfa_hits = match_dfa(detectors, shown)

                if regex_hits:
                    st.warning("Regex hits:")
                    for h in regex_hits: st.write(f"- {h}")
                    log_alert("Regex", "Live", payload, regex_hits, severity="medium")
                if dfa_hits:
                    st.error("DFA hits:")
                    for h in dfa_hits: st.write(f"- {h}")
                    log_alert("DFA", "Live", payload, dfa_hits, severity="high")

                # ANN (best-effort mapping)
                if model_ready:
                    row = packet_to_nsl_row(p)
                    out = predict_with_explanations(row, preprocessors, top_k=3)
                    pred = out["preds"].iloc[0].to_dict()
                    exp = out["explanations"][0]
                    st.info(f"ANN → prob_attack={pred['prob_attack']:.2f}, pred_attack={int(pred['pred_attack'])}")
                    with st.expander("Why ANN thinks this:", expanded=False):
                        tf_df = pd.DataFrame(exp["top_features"], columns=["Feature", "Contribution (0-1)", "Meaning"])
                        st.dataframe(tf_df)
                        st.caption(exp["summary"])
                    if int(pred["pred_attack"]) == 1:
                        log_alert("ANN", "Live", payload, ["ANN:attack"], severity="high")

                rows.append({
                    "packet": i,
                    "regex_hits": "; ".join(regex_hits),
                    "dfa_hits": "; ".join(dfa_hits),
                })

            st.success("Capture complete.")
            if rows:
                df = pd.DataFrame(rows)
                st.write("Summary:")
                st.dataframe(df)

# ---------- Logs viewer & export ----------
st.markdown("---")
st.header("📂 Alerts Log")
if st.button("Show Alerts Log"):
    try:
        with open("logs/alerts.jsonl", "r", encoding="utf-8") as f:
            lines = [eval(l) if l.strip().startswith("{") else None for l in f.readlines()]
        lines = [x for x in lines if isinstance(x, dict)]
        if not lines:
            st.info("No alerts yet.")
        else:
            df = pd.DataFrame(lines)
            st.dataframe(df)
            # Download CSV
            try:
                with open("logs/alerts.csv", "rb") as f:
                    st.download_button("Download alerts.csv", f, file_name="alerts.csv", mime="text/csv")
            except FileNotFoundError:
                pass
    except FileNotFoundError:
        st.info("No alerts logged yet.")
