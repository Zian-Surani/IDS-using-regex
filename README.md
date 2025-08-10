# IDS using Regex + DFA

An **Intrusion Detection System (IDS)** that scans packet payloads for suspicious patterns using **Regular Expressions** and **Deterministic Finite Automata (DFA)** conversion.  
This hybrid approach helps detect worms, exploits, and malicious payloads that may bypass simple regex checks.

<img width="1919" height="956" alt="image" src="https://github.com/user-attachments/assets/10835213-aa64-4b9c-bf76-f37f760ad52f" />

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

```
🖥 Usage
Open the Streamlit UI.

Paste a payload (HTTP request, form data, etc.) into the input box.

Choose Regex, DFA, or Both detection mode.

View results:

✅ Safe — No suspicious patterns detected.

⚠️ Match — Potentially suspicious activity detected.

🚨 Both Match — High confidence threat.

Optionally upload a CSV in NSL-KDD format for ANN-based classification.

📊 ANN Model
The ANN is trained using the NSL-KDD dataset, performing binary classification:

0 → Normal traffic

1 → Attack

Preprocessing includes:

One-hot encoding for categorical features

Standard scaling for numeric features

📁 Project Structure

IDS-using-regex/
│

├── ui_app.py                  # Streamlit UI

├── regex_dfa_matcher.py       # Regex/DFA matching logic

├── ann_model.py               # ANN training

├── ann_classifier.py          # ANN prediction

├── packet_sniffer.py          # Packet capture

├── payload_extractor.py       # Extract payload from packets

├── signatures.txt             # Detection patterns

├── requirements.txt           # Dependencies

├── model/                     # Trained ANN model

├── preprocessors/             # Saved preprocessing objects

└── scripts/
   
   └── bench_regex_vs_dfa.py   # Benchmark script

## 📈 Benchmark
You can test performance differences between Regex and DFA with:


```python scripts/bench_regex_vs_dfa.py```

## 📜 License
MIT License

---

### **📄 .gitignore**
```gitignore
# Python cache
__pycache__/
*.pyc
*.pyo
*.pyd

# Virtual environments
venv/
.env/

# Models & preprocessors
model/
preprocessors/

# Logs
logs/
*.log

# Streamlit cache
.streamlit/

# Data files
*.csv
*.txt

# OS files
.DS_Store
Thumbs.db





