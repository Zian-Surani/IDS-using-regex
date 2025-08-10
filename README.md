# AI-Powered Intrusion Detection System (Deployable)

This project trains an ANN on the NSL-KDD dataset and provides a Streamlit UI for:
- Training the ANN (downloads NSL-KDD automatically)
- Classifying uploaded NSL-KDD-format records
- Testing regex-based DFA matching on pasted payload text
- Simple packet-sniff fallback (requires admin and scapy)

## Quick Start (Windows)
1. Create & activate venv:
python -m venv venv
.\venv\Scripts\activate

2. Install dependencies:
pip install -r requirements.txt

3. (Optional) Train model (recommended before classification):
python train_ann_model.py

This script will download NSL-KDD training/test files and train a model stored in `model/ann_model.h5`.

4. Run the Streamlit UI:
streamlit run ui_app.py

If `streamlit` isn't recognized, use:
python -m streamlit run ui_app.py



## Notes
- Model training can take time; use a GPU or run fewer epochs for quick tests.
- Packet sniffing requires admin/root and may not work on Windows without npcap.
- The train script downloads files from GitHub raw URLs (defcom17/NSL_KDD).
