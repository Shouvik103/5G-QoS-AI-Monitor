"""
5G QoS Degradation Detection — Backend
=======================================
Supports two modes:
  --pcap   : reads a recorded .pcap file (offline / demo)
  --live   : sniffs live traffic on a network interface (real-time)

In both modes the output schema is identical so the dashboard
frontend does not need any changes.

Output JSON schema:
  sessions   : list of 30s windows with QoS features + status
  summary    : aggregate stats (for header cards)
  alerts     : degraded windows sorted worst-first

Usage:
  # Offline (pcap file)
  python backend_5g_qos.py --pcap longrun.pcap --out output.json
  python backend_5g_qos.py --pcap longrun.pcap --out output.json --serve

  # Live capture (needs root / sudo)
  sudo python backend_5g_qos.py --live --iface eth0 --serve
  sudo python backend_5g_qos.py --live --iface wlan0 --duration 300 --serve

Dependencies:
  pip install scikit-learn pandas numpy scapy
"""

import struct
import socket
import argparse
import json
import time
import threading
import numpy as np
import pandas as pd
from collections import deque
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# ─── CONSTANTS ────────────────────────────────────────────────
WINDOW_SIZE           = 30      # seconds per analysis window
CONTAMINATION         = 0.10    # expected anomaly rate
LATENCY_THRESH        = 60.0    # ms
RESOURCE_ALLOC_THRESH = 60.0    # %
BW_GAP_THRESH         = 0.0     # Mbps

PORT_MAP = {
    38412: "N2-AMF",
    38413: "N2-gNB",
    38472: "F1-C-DU",
    38473: "F1-C-CU",
}


# ════════════════════════════════════════════════════════════════
# PCAP FILE READER
# ════════════════════════════════════════════════════════════════

def read_pcap(path):
    packets = []
    with open(path, "rb") as f:
        magic = f.read(4)
        if magic not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
            raise ValueError("Not a valid pcap file")
        endian = "<" if magic == b"\xd4\xc3\xb2\xa1" else ">"
        f.read(20)
        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                break
            ts_sec, ts_usec, incl_len, _ = struct.unpack(endian + "IIII", hdr)
            data = f.read(incl_len)
            packets.append((ts_sec + ts_usec / 1e6, incl_len, data))
    return packets


# ════════════════════════════════════════════════════════════════
# LIVE CAPTURE  (scapy sniffer in background thread)
# ════════════════════════════════════════════════════════════════

def live_capture(iface, duration, packet_buffer):
    try:
        from scapy.all import sniff
    except ImportError:
        raise ImportError("scapy not installed — run: pip install scapy")

    print(f"🔴  Live capture started on: {iface}")
    start = time.time()

    def handle(pkt):
        raw = bytes(pkt)
        packet_buffer.append((time.time(), len(raw), raw))

    stop_fn = (lambda p: time.time() - start > duration) if duration > 0 else None
    sniff(iface=iface, prn=handle, store=False, stop_filter=stop_fn)
    print("🔴  Capture ended.")


# ════════════════════════════════════════════════════════════════
# PACKET PARSER
# ════════════════════════════════════════════════════════════════

def _ip_offset(data):
    # Common L2 header sizes before IPv4:
    # SLL2=20, Ethernet=14, SLL=16, Raw=0
    for off in (20, 14, 16, 0):
        if len(data) > off and (data[off] & 0xF0) == 0x40:
            return off
    return None


def parse_packets(raw_list):
    rows = []
    for ts, pkt_len, data in raw_list:
        off = _ip_offset(data)
        if off is None or len(data) < off + 20:
            continue
        ihl       = (data[off] & 0x0F) * 4
        total_len = struct.unpack(">H", data[off + 2:off + 4])[0]
        sctp_s    = off + ihl
        if len(data) < sctp_s + 4:
            continue
        sp  = struct.unpack(">H", data[sctp_s:sctp_s + 2])[0]
        dp  = struct.unpack(">H", data[sctp_s + 2:sctp_s + 4])[0]
        app = PORT_MAP.get(sp) or PORT_MAP.get(dp) or "WiFi/Other"
        rows.append({"timestamp": ts, "pkt_size": total_len,
                     "app": app, "_raw": data})

    return pd.DataFrame(rows) if rows else pd.DataFrame(
        columns=["timestamp", "pkt_size", "app", "_raw"])


# ════════════════════════════════════════════════════════════════
# SCTP SACK GAP COUNTER
# ════════════════════════════════════════════════════════════════

def count_sack_gaps(data, ip_off):
    ihl    = (data[ip_off] & 0x0F) * 4
    sctp_s = ip_off + ihl
    if len(data) < sctp_s + 12:
        return 0
    offset = sctp_s + 12
    gaps   = 0
    while offset + 4 <= len(data):
        ctype = data[offset]
        clen  = struct.unpack(">H", data[offset + 2:offset + 4])[0]
        if clen < 4:
            break
        if ctype == 0x03 and clen >= 16:
            gaps += struct.unpack(">H", data[offset + 12:offset + 14])[0]
        offset += clen + (4 - clen % 4) % 4
    return gaps


# ════════════════════════════════════════════════════════════════
# FEATURE EXTRACTION  (30s windows)
# ════════════════════════════════════════════════════════════════

def extract_windows(df_pkts):
    if df_pkts.empty:
        return pd.DataFrame()

    df_pkts = df_pkts.sort_values("timestamp").reset_index(drop=True)
    t       = df_pkts["timestamp"].min()
    t_end   = df_pkts["timestamp"].max()
    windows = []
    win_id  = 0

    while t + WINDOW_SIZE <= t_end:
        win = df_pkts[(df_pkts["timestamp"] >= t) &
                      (df_pkts["timestamp"] <  t + WINDOW_SIZE)]
        if len(win) < 3:
            t += WINDOW_SIZE
            continue

        times = win["timestamp"].values
        sizes = win["pkt_size"].values
        ipds  = np.diff(times) * 1000
        ipds  = ipds[ipds > 0]

        if len(ipds) == 0:
            t += WINDOW_SIZE
            continue

        latency_ms      = float(np.mean(ipds))
        jitter          = float(np.std(ipds))
        throughput_mbps = float(sizes.sum() * 8 / WINDOW_SIZE / 1e6)

        total_gaps = sum(
            count_sack_gaps(raw, o)
            for raw in win["_raw"].values
            for o in [_ip_offset(raw)] if o is not None
        )
        delivered      = max(len(win) - total_gaps, 0)
        resource_alloc = float(delivered / len(win) * 100)

        median_ipd = float(np.median(ipds))
        loss_gaps  = int((ipds > 5 * median_ipd).sum())
        loss_rate  = loss_gaps / len(ipds)
        signal_dbm = float(-50 - loss_rate * 60)
        burstiness = float(np.max(ipds) / np.mean(ipds)) if np.mean(ipds) > 0 else 0.0
        app_type   = win["app"].value_counts().idxmax()

        windows.append({
            "session_id":           win_id,
            "window_start":         pd.to_datetime(t, unit="s").isoformat(),
            "application_type":     app_type,
            "latency_ms":           round(latency_ms, 2),
            "jitter_ms":            round(jitter, 2),
            "signal_strength_dbm":  round(signal_dbm, 2),
            "throughput_mbps":      round(throughput_mbps, 4),
            "resource_alloc_pct":   round(resource_alloc, 2),
            "loss_rate":            round(loss_rate, 4),
            "burstiness":           round(burstiness, 3),
            "_tp_raw":              throughput_mbps,
        })
        t += WINDOW_SIZE
        win_id += 1

    if not windows:
        return pd.DataFrame()

    df_w = pd.DataFrame(windows)
    median_tp      = df_w["_tp_raw"].median()
    df_w["bw_gap"] = (df_w["_tp_raw"] - median_tp).round(4)
    df_w.drop(columns=["_tp_raw"], inplace=True)
    return df_w


# ════════════════════════════════════════════════════════════════
# ML PIPELINE
# ════════════════════════════════════════════════════════════════

def run_model(df_w):
    features = ["signal_strength_dbm", "latency_ms",
                "bw_gap", "resource_alloc_pct"]
    X        = df_w[features].copy()
    scaler   = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(n_estimators=100, contamination=CONTAMINATION,
                            random_state=42)
    model.fit(X_scaled)
    df_w["anomaly_score"] = model.decision_function(X_scaled).round(4)
    df_w["_ar"]           = model.predict(X_scaled)

    def classify(row):
        if row["_ar"] == -1:
            if (row["latency_ms"]         > LATENCY_THRESH or
                row["resource_alloc_pct"] < RESOURCE_ALLOC_THRESH or
                row["bw_gap"]             < BW_GAP_THRESH):
                return "QoS Degraded"
            return "Unusual but Acceptable"
        return "Normal"

    df_w["qos_status"] = df_w.apply(classify, axis=1)
    df_w.drop(columns=["_ar"], inplace=True)
    return df_w


# ════════════════════════════════════════════════════════════════
# OUTPUT FORMATTER
# ════════════════════════════════════════════════════════════════

def to_dashboard_json(df_w):
    sessions = df_w.rename(columns={
        "session_id":          "User_ID",
        "application_type":    "Application_Type",
        "signal_strength_dbm": "Signal_Strength_dBm",
        "latency_ms":          "Latency_ms",
        "bw_gap":              "BW_Gap",
        "resource_alloc_pct":  "Resource_Allocation_pct",
        "anomaly_score":       "Anomaly_Score",
        "qos_status":          "QoS_Status",
    }).to_dict(orient="records")

    total    = len(df_w)
    normal   = int((df_w["qos_status"] == "Normal").sum())
    degraded = int((df_w["qos_status"] == "QoS Degraded").sum())
    unusual  = int((df_w["qos_status"] == "Unusual but Acceptable").sum())

    summary = {
        "total_sessions":       total,
        "normal":               normal,
        "degraded":             degraded,
        "unusual":              unusual,
        "degradation_rate_pct": round(degraded / total * 100, 1) if total else 0,
        "avg_latency_ms":       round(df_w["latency_ms"].mean(), 2),
        "avg_signal_dbm":       round(df_w["signal_strength_dbm"].mean(), 2),
        "avg_resource_alloc":   round(df_w["resource_alloc_pct"].mean(), 2),
        "last_updated":         pd.Timestamp.now().isoformat(),
    }

    alerts = (df_w[df_w["qos_status"] == "QoS Degraded"]
              .sort_values("anomaly_score")
              [["session_id", "window_start", "application_type",
                "latency_ms", "signal_strength_dbm",
                "resource_alloc_pct", "bw_gap", "anomaly_score", "qos_status"]]
              .to_dict(orient="records"))

    return {"sessions": sessions, "summary": summary, "alerts": alerts}


# ════════════════════════════════════════════════════════════════
# HTTP SERVER
# ════════════════════════════════════════════════════════════════

def serve(get_payload_fn, port=5050):
    from http.server import HTTPServer, BaseHTTPRequestHandler

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = json.dumps(get_payload_fn(), default=str).encode()
            self.send_response(200)
            self.send_header("Content-Type",  "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_OPTIONS(self):
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
            self.end_headers()

        def log_message(self, *_):
            pass

    print(f"\n🟢  API live → http://localhost:{port}/")
    print(f"    GET /  → returns full JSON payload")
    print(f"    Ctrl+C to stop\n")
    HTTPServer(("", port), Handler).serve_forever()


# ════════════════════════════════════════════════════════════════
# LIVE LOOP  (model reruns every WINDOW_SIZE seconds)
# ════════════════════════════════════════════════════════════════

def live_loop(iface, out_path, port, duration):
    packet_buffer  = deque()
    payload_holder = {"data": {"sessions": [], "summary": {}, "alerts": []}}
    lock           = threading.Lock()

    # Sniffer thread
    cap_thread = threading.Thread(
        target=live_capture,
        args=(iface, duration, packet_buffer),
        daemon=True
    )
    cap_thread.start()

    # HTTP server thread
    def get_payload():
        with lock:
            return payload_holder["data"]

    srv_thread = threading.Thread(
        target=serve, args=(get_payload, port), daemon=True
    )
    srv_thread.start()

    print(f"⏱   Analysing every {WINDOW_SIZE}s ...")
    window_num = 0

    while True:
        time.sleep(WINDOW_SIZE)

        batch  = list(packet_buffer)
        cutoff = time.time() - WINDOW_SIZE * 2
        packet_buffer.clear()
        for p in batch:
            if p[0] >= cutoff:
                packet_buffer.append(p)

        if len(batch) < 3:
            print(f"  [{window_num}] waiting for packets...")
            window_num += 1
            continue

        df_pkts = parse_packets(batch)
        df_w    = extract_windows(df_pkts)

        if df_w.empty:
            print(f"  [{window_num}] no complete windows yet")
            window_num += 1
            continue

        df_w    = run_model(df_w)
        payload = to_dashboard_json(df_w)

        with lock:
            payload_holder["data"] = payload

        with open(out_path, "w") as f:
            json.dump(payload, f, indent=2, default=str)

        deg   = payload["summary"].get("degraded", 0)
        total = payload["summary"].get("total_sessions", 0)
        flag  = "🔴 DEGRADED" if deg > 0 else "🟢 OK"
        print(f"  [{window_num}] {total} windows | {deg} degraded | {flag}")
        window_num += 1

        if duration > 0 and not cap_thread.is_alive():
            print("✅  Duration reached. Exiting.")
            break


# ════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="5G QoS Degradation Detection Backend",
        formatter_class=argparse.RawTextHelpFormatter
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--pcap",  metavar="FILE", help="Path to .pcap file")
    mode.add_argument("--live",  action="store_true", help="Live capture mode")

    parser.add_argument("--iface",    default="eth0",
                        help="Network interface for live mode (default: eth0)")
    parser.add_argument("--duration", type=int, default=0,
                        help="Live capture duration seconds (0=forever)")
    parser.add_argument("--out",      default="qos_output.json",
                        help="Output JSON file")
    parser.add_argument("--serve",    action="store_true",
                        help="Start HTTP API on --port")
    parser.add_argument("--port",     type=int, default=5050,
                        help="HTTP server port (default: 5050)")
    args = parser.parse_args()

    if args.live:
        print("=" * 55)
        print("  5G QoS Backend — LIVE MODE")
        print("=" * 55)
        live_loop(args.iface, args.out, args.port, args.duration)
    else:
        print("=" * 55)
        print("  5G QoS Backend — PCAP MODE")
        print("=" * 55)
        print(f"📂  Reading {args.pcap} ...")
        raw = read_pcap(args.pcap)
        print(f"    {len(raw)} packets loaded")

        print("🔍  Parsing ...")
        df_pkts = parse_packets(raw)
        print(f"    {len(df_pkts)} IPv4 packets parsed")

        print("📊  Extracting windows ...")
        df_w = extract_windows(df_pkts)
        print(f"    {len(df_w)} windows extracted")

        if df_w.empty:
            print("❌  No windows — check pcap file"); return

        print("🤖  Running Isolation Forest ...")
        df_w    = run_model(df_w)
        payload = to_dashboard_json(df_w)

        d = payload["summary"]["degraded"]
        t = payload["summary"]["total_sessions"]
        print(f"    {d}/{t} degraded ({payload['summary']['degradation_rate_pct']}%)")

        with open(args.out, "w") as f:
            json.dump(payload, f, indent=2, default=str)
        print(f"✅  Saved → {args.out}")

        if args.serve:
            serve(lambda: payload, port=args.port)


if __name__ == "__main__":
    main()
