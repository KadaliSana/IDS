# SHIELD — AI-Powered Intrusion Detection

Privacy-preserving IDS using Zeek + ML ensemble. No packet decryption.

## Quick start

### 1. Install Zeek
```bash
# Debian / Raspberry Pi OS
sudo apt install zeek

# Start capturing (run in a separate terminal)
sudo zeek -i eth0 policy/protocols/ssl/ja3.zeek LogAscii::use_json=T
```

### 2. Install Python dependencies
```bash
pip install -r requirements.txt
# On Raspberry Pi, replace tensorflow with:
pip install tflite-runtime
```

### 3. Train models (first time)
```bash
# Download CICIDS-2017 from https://www.unb.ca/cic/datasets/ids-2017.html
# Convert to Zeek format or use the label CSV directly:
python main.py --mode train \
    --conn-log /var/log/zeek/conn.log \
    --ssl-log  /var/log/zeek/ssl.log  \
    --labels-csv data/cicids_labels.csv
```

### 4. Run live detection
```bash
# Terminal 1: Zeek (already running from step 1)

# Terminal 2: SHIELD pipeline
python main.py --mode live

# Terminal 3: Dashboard API
uvicorn dashboard.api:app --host 0.0.0.0 --port 8000
```

### 5. Test with a saved log
```bash
python main.py --mode replay \
    --conn-log tests/sample_conn.log \
    --ssl-log  tests/sample_ssl.log
```

## Project structure

```
shield/
├── config/
│   └── settings.py          # all tuneable parameters
├── capture/
│   └── zeek_reader.py       # zat-based multi-log tailer + uid joiner
├── features/
│   └── extractor.py         # 40-feature vector extraction
├── models/
│   ├── detectors.py         # IsoForest, RF, LSTM, Statistical
│   └── artefacts/           # saved .joblib / .tflite files
├── scoring/
│   └── risk_scorer.py       # ensemble fusion + SHAP + alert generation
├── response/
│   └── auto_block.py        # iptables block with auto-expiry
├── dashboard/
│   └── api.py               # FastAPI REST + WebSocket
├── main.py                  # entry point
└── requirements.txt
```

## Tuning

Edit `config/settings.py`:
- `ALERT_THRESHOLD` — lower = more sensitive (more false positives)
- `BLOCK_THRESHOLD` — score above which auto-block fires
- `ENSEMBLE_WEIGHTS` — rebalance detector contributions
- `AUTO_BLOCK_ENABLED` — set True to enable iptables auto-blocking
- `JA3_BLOCKLIST` — add known-malicious JA3 hashes
