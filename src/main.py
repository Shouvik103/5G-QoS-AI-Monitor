# main.py
from fastapi import FastAPI
from pydantic import BaseModel
import joblib
import pandas as pd
import numpy as np
from pathlib import Path

app = FastAPI()

def _resolve_artifact(filename: str) -> Path:
    base_dir = Path(__file__).resolve().parent          # src/
    project_root = base_dir.parent                      # project root
    candidates = [
        project_root / "models" / filename,             # models/ dir (standard)
        base_dir / filename,                            # src/ (fallback)
        project_root / filename,                        # project root (fallback)
        Path.cwd() / filename,                          # cwd (fallback)
    ]

    for candidate in candidates:
        if candidate.exists():
            return candidate

    checked = ", ".join(str(path) for path in candidates)
    raise FileNotFoundError(f"Could not find {filename}. Checked: {checked}")


# Load the trained AI model and scaler
model = joblib.load(_resolve_artifact("model.joblib"))
scaler = joblib.load(_resolve_artifact("scaler.joblib"))

# Define what the incoming 5G network data looks like
class NetworkTelemetry(BaseModel):
    Signal_Strength: float
    Download_Speed: float
    Upload_Speed: float
    Latency: float
    Jitter: float
    Battery_Level: float
    Connected_Duration: float
    Handover_Count: int
    Data_Usage: float
    Network_Congestion_Level: int
    BW_Gap: float
    Resource_Allocation_pct: float

@app.post("/predict_qos")
def predict_status(data: NetworkTelemetry):
    # Convert incoming JSON into a DataFrame with the exact column names the model expects
    input_data = pd.DataFrame([{
        'Signal_Strength_dBm': data.Signal_Strength,
        'Latency_ms': data.Latency,
        'BW_Gap': data.BW_Gap,
        'Resource_Allocation_pct': data.Resource_Allocation_pct
    }])
    
    # Scale the raw input data using the scaler exported from Colab
    scaled_data = scaler.transform(input_data)

    # Model expects 5 features: 4 scaled telemetry values + congestion level
    model_input = np.hstack([
        scaled_data,
        np.array([[data.Network_Congestion_Level]], dtype=float),
    ])
    
    # IsolationForest prediction (-1 = Anomaly, 1 = Normal)
    prediction = model.predict(model_input)[0]

    # Mark critical only when model anomaly aligns with degraded network conditions.
    severe_degradation = (
        data.Signal_Strength < -100.0
        or data.Latency > 45.0
        or data.BW_Gap > 1.2
        or data.Resource_Allocation_pct < 45.0
        or (data.Network_Congestion_Level >= 2 and data.Latency > 30.0)
    )
    risk_score = 1 if (prediction == -1 and severe_degradation) else 0
    
    status = "Critical Warning : Anomaly Detected" if risk_score == 1 else "Network Healthy"
    return {"QoS_Status": status, "Risk_Score": risk_score}