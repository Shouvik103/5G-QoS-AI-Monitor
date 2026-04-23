# 🛡️ Private 5G Network QoS AI Monitor

An AI-powered real-time Quality of Service (QoS) monitoring dashboard for Private 5G Networks. Uses a machine learning model to predict dropped connections and assess network health in real time.

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green?logo=fastapi)
![Streamlit](https://img.shields.io/badge/Streamlit-1.30+-red?logo=streamlit)
![scikit-learn](https://img.shields.io/badge/scikit--learn-ML-orange?logo=scikitlearn)

---

## 📋 Overview

This system simulates and monitors 5G network telemetry parameters — **Latency, Jitter, Signal Strength, Throughput, Ping** — and uses a **Gradient Boosting Classifier** to predict whether a connection is at risk of being dropped.

### Key Features

- **Real-Time AI Prediction** — ML model classifies network state as *Safe* or *At Risk* every second
- **Live Telemetry Charts** — Filled area charts with gradient styling for all key metrics
- **Risk Score Trend** — Bar + line overlay chart tracking network stress over time
- **AI Prediction Analytics** — Summary panel with Safe/Risk counts and percentages
- **Recent Events Log** — Timestamped event history with one-click CSV download (last 25 events)
- **Congestion Simulation** — Adjustable network congestion level via sidebar slider
- **System Health Bar** — Visual stress indicator based on real-time metrics

---

## 🏗️ Architecture

```
┌─────────────────┐     POST /predict_qos     ┌──────────────────┐
│   Streamlit UI  │ ──────────────────────────▶│  FastAPI Backend  │
│  (dashboard.py) │◀────────────────────────── │    (main.py)      │
│                 │     JSON Response          │                  │
│  • Live Charts  │                            │  • ML Inference  │
│  • Metrics      │                            │  • GBClassifier  │
│  • Risk History │                            │  • Pydantic I/O  │
└─────────────────┘                            └──────────────────┘
```

---

## 📂 Project Structure

| File | Description |
|------|-------------|
| `main.py` | FastAPI backend — loads ML model and serves predictions via `/predict_qos` |
| `dashboard.py` | Streamlit dashboard — real-time telemetry visualization and AI monitoring |
| `train_model.py` | Model training script — trains a GradientBoostingClassifier on 5G data |
| `model.joblib` | Pre-trained ML model file |
| `scaler.joblib` | Feature scaler used before model inference |
| `high_accuracy_5g_data.csv` | Training dataset with 5G network telemetry features |

---

## 🚀 Getting Started

### Prerequisites

- Python 3.10+
- pip

### Installation

```bash
# Clone the repository
git clone https://github.com/Shouvik103/5G_UseCase.git
cd 5G_UseCase

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On macOS/Linux

# Install dependencies
pip install fastapi uvicorn streamlit pandas scikit-learn joblib altair requests pydantic
```

### Train the Model (Optional)

If you want to retrain the ML model:

```bash
python train_model.py
```

### Run the Application

**Terminal 1 — Start the FastAPI backend:**
```bash
uvicorn main:app --reload
```

**Terminal 2 — Start the Streamlit dashboard:**
```bash
streamlit run dashboard.py
```

Open [http://localhost:8501](http://localhost:8501) in your browser.

---

## 🧠 ML Model Details

| Parameter | Value |
|-----------|-------|
| Algorithm | Gradient Boosting Classifier |
| Estimators | 150 |
| Max Depth | 6 |
| Learning Rate | 0.1 |
| Target | `Engineered_Dropped_Connection` (0 = Healthy, 1 = Dropped) |

### Input Features

| Feature | Unit |
|---------|------|
| Signal Strength | dBm |
| Download Speed | Mbps |
| Upload Speed | Mbps |
| Latency | ms |
| Jitter | ms |
| Battery Level | % |
| Connected Duration | min |
| Handover Count | count |
| Data Usage | MB |
| Network Congestion Level | 1–3 |

---

## 📊 Dashboard Panels

- **Metric Cards** — Latency, Jitter, Signal, Download, Upload, Ping with real-time values
- **Area Charts** — Filled gradient charts for each telemetry metric
- **AI Prediction Summary** — Safe / At Risk / Total counts with progress bar
- **Risk Score Trend** — Bar chart + teal trend line overlay
- **Recent Events** — Scrollable log with download icon for CSV export
- **KPI Summary** — Running averages for all metrics

---

## 🛠️ Tech Stack

- **Backend:** FastAPI + Uvicorn
- **Frontend:** Streamlit + Altair
- **ML:** scikit-learn (GradientBoostingClassifier)
- **Data:** pandas, NumPy
- **Serialization:** joblib

---

## 📄 License

This project is for educational purposes as part of the **Introduction to 5G** coursework.
