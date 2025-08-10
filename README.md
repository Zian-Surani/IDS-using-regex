# IDS using Regex + DFA

An **Intrusion Detection System (IDS)** that scans packet payloads for suspicious patterns using **Regular Expressions** and **Deterministic Finite Automata (DFA)** conversion.  
This hybrid approach helps detect worms, exploits, and malicious payloads that may bypass simple regex checks.

---

## 🚀 Features
- **Regex Matching** — Fast and flexible pattern scanning
- **DFA Matching** — Converts regex to deterministic finite automata for state-based detection
- **Dual Mode** — Runs both methods and flags high-confidence threats
- **ANN Integration** — Uses an Artificial Neural Network trained on the NSL-KDD dataset for anomaly detection
- **Streamlit Dashboard** — User-friendly UI with visual detection results and explanations
- **Packet Capture Demo** — Capture live packets and scan in real time (requires privileges)

---

## 📦 Quickstart
```bash
# Clone the repository
git clone https://github.com/Zian-Surani/IDS-using-regex.git
cd IDS-using-regex

# Install dependencies
pip install -r requirements.txt

# (Optional) Train ANN Model
python ann_model.py

# Run Streamlit app
streamlit run ui_app.py
