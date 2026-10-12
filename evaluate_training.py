#!/usr/bin/env python3

import argparse
import csv
import json
import dpkt
from collections import Counter
from pathlib import Path
from datetime import datetime, timezone, timedelta

def parse_args():
    parser = argparse.ArgumentParser(description="Evaluate Suricata alerts against csv ground truth (training rules).")

    parser.add_argument(
        "-e",
        "--eve",
        required=True,
        type=Path,
        help="Path to Suricata eve.json"
    )

    parser.add_argument(
        "-c",
        "--csv",
        required=True,
        type=Path,
        help="Path to ground-truth csv"
    )

    parser.add_argument(
        "-p",
        "--pcap",
        required=True,
        type=Path,
        help="Path to pcap file"
    )

    parser.add_argument(
        "-s",
        "--sid",
        type=int,
        required=False,
        help="Suricata SID to evaluate"
    )

    return parser.parse_args()

def load_pcap_timestamps(pcap_path):
    ts_to_frame = {}
    tz = timezone(timedelta(hours=1))

    with open(pcap_path, "rb") as file:
        reader = dpkt.pcap.Reader(file)
        i = 0
        while True:
            try:
                ts, _ = next(reader)
                i += 1

                dt = datetime.fromtimestamp(ts, tz=tz)
                ts_iso = dt.strftime("%H:%M:%S.%f")
                ts_to_frame[ts_iso] = str(i)
            except StopIteration:
                break
            except Exception:
                i += 1
                continue

    return ts_to_frame

def bidirectional_key(src_ip, src_port, dst_ip, dst_port, proto):
    a = (src_ip, src_port)
    b = (dst_ip, dst_port)
    if a > b:
        a, b = b, a
    return (a[0], a[1], b[0], b[1], proto)

def read_ground_truth(csv_path, ts_to_frame):
    flows = {}
    total_rows = 0
    invalid_rows = 0
    attack_rows = 0
    benign_rows = 0

    with open(csv_path, newline="", encoding="utf-8", errors="replace") as file:
        reader = csv.DictReader(file)

        required = ["ip.src_host", "ip.dst_host", "tcp.srcport", "tcp.dstport"]
        missing = [c for c in required if c not in reader.fieldnames]
        if missing:
            raise ValueError("Missing CSV columns: " + ", ".join(missing))

        label_column = next((c for c in reader.fieldnames if "label" in c.lower()), None)
        if label_column is None:
            raise ValueError("No column containing label found in CSV")

        for row in reader:
            total_rows += 1

            try:
                ts_field = row["frame.time"].strip()
                if not ts_field:
                    invalid_rows += 1
                    continue

                parts = ts_field.split(" ")
                if len(parts) < 2:
                    invalid_rows += 1
                    continue

                time = parts[1][:15]
                frame_number = ts_to_frame.get(time)
                if not frame_number:
                    invalid_rows += 1
                    continue

                src_ip = row["ip.src_host"].strip()
                dst_ip = row["ip.dst_host"].strip()

                if row["tcp.srcport"] or row["tcp.dstport"]:
                    proto = "TCP"
                    src_port = int(float(row["tcp.srcport"] or 0))
                    dst_port = int(float(row["tcp.dstport"] or 0))
                elif row["udp.port"]:
                    proto = "UDP"
                    src_port = int(float(row["udp.port"] or 0))
                    dst_port = int(float(row["udp.port"] or 0))
                elif row["icmp.checksum"] or row["icmp.seq_le"]:
                    proto = "ICMP"
                    src_port = 0
                    dst_port = 0
                else:
                    proto = "UNKNOWN"
                    src_port = 0
                    dst_port = 0

                label = row[label_column].strip()

                key = bidirectional_key(src_ip, src_port, dst_ip, dst_port, proto)

            except (ValueError, TypeError, KeyError):
                invalid_rows += 1
                continue

            if key not in flows:
                flows[key] = {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "proto": proto,
                    "label": label,
                    "frames": [],
                }

            flows[key]["frames"].append(frame_number)

    for flow in flows.values():
        if flow["label"] == "1":
            attack_rows += len(flow["frames"])
        else:
            benign_rows += len(flow["frames"])

    return flows, total_rows, invalid_rows, attack_rows, benign_rows

def read_eve(eve_path, sid):

    alert_frames = set()

    total_alerts = 0
    target_alerts = 0
    invalid_alerts = 0

    signatures = Counter()

    with open(eve_path, encoding="utf-8", errors="replace") as file:
        for line in file:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if event.get("event_type") != "alert":
                continue

            total_alerts += 1
            alert = event.get("alert", {})
            alert_sid = alert.get("signature_id")

            if sid is not None and alert_sid != sid:
                continue

            target_alerts += 1
            signature = alert.get("signature", "UNKNOWN")
            signatures[signature] += 1

            pcap_cnt = event.get("pcap_cnt")
            if pcap_cnt is None:
                invalid_alerts += 1
                continue

            frame_number = str(pcap_cnt)
            alert_frames.add(frame_number)

    return {
        "alert_frames": alert_frames,
        "total_alerts": total_alerts,
        "target_alerts": target_alerts,
        "invalid_alerts": invalid_alerts,
        "signatures": signatures,
    }

def evaluate(flows, eve_data):
    alert_frames = eve_data["alert_frames"]

    tp = 0
    fn = 0
    fp = 0
    tn = 0

    for flow in flows.values():
        attack = flow["label"] == "1"

        detected = any(f in alert_frames for f in flow["frames"])

        for frame_number in flow["frames"]:
            if attack and detected:
                tp += 1
            elif attack and not detected:
                fn += 1
            elif not attack and detected:
                fp += 1
            elif not attack and not detected:
                tn += 1

    return tp, fn, fp, tn

def main():
    args = parse_args()

    print("Starting Suricata alert evaluation...")
    print(f"EVE : {args.eve}")
    print(f"CSV : {args.csv}")
    print(f"SID : {'all' if args.sid is None else args.sid}")
    print()

    print("Loading PCAP timestamps...")

    ts_to_frame = load_pcap_timestamps(args.pcap)

    print(f"PCAP contains {len(ts_to_frame)} frames")

    print("Reading csv ground truth...")

    (frames, total_rows, invalid_rows, attack_frames, benign_frames) = read_ground_truth(args.csv, ts_to_frame)

    print(f"CSV rows             : {total_rows:,}")
    print(f"CSV unique frames    : {len(frames):,}")
    print(f"Attack frames        : {attack_frames:,}")
    print(f"Benign frames        : {benign_frames:,}")
    print(f"Invalid frames       : {invalid_rows:,}")
    print()

    print("Reading Suricata alerts...")

    eve_data = read_eve(args.eve, args.sid)

    print(f"Suricata total alerts : {eve_data['total_alerts']:,}")
    print(f"Alerts evaluated for {'all' if args.sid is None else args.sid} SID : {eve_data['target_alerts']:,}")
    print(f"Invalid evaluated alerts : {eve_data['invalid_alerts']:,}")
    print(f"Alert frames : {len(eve_data['alert_frames']):,}")
    print()

    if eve_data["signatures"]:
        print("Evaluated signatures:")
        for signature, count in eve_data["signatures"].most_common():
            print(f"  {count:6,}  {signature}")
        print()

    print("Computing evaluation...")
    tp, fn, fp, tn = evaluate(frames, eve_data)
    total = tp + fn + fp + tn

    print("Metrics:")
    print(f"TP    : {tp:,}")
    print(f"FN    : {fn:,}")
    print(f"FP    : {fp:,}")
    print(f"TN    : {tn:,}")
    print(f"Total : {total:,}")
    print()

    print(f"Recall    : {tp / (tp + fn):.4%}" if tp + fn else "Recall    : N/A")
    print(f"Precision : {tp / (tp + fp):.4%}" if tp + fp else "Precision : N/A")
    print(f"FPR       : {fp / (fp + tn):.4%}" if fp + tn else "FPR       : N/A")
    print(f"TNR       : {tn / (tn + fp):.4%}" if tn + fp else "TNR       : N/A")
    print(f"Accuracy  : {(tp + tn) / total:.4%}" if total else "Accuracy : N/A")
    print(f"F1        : {2 * tp / (2 * tp + fp + fn):.4%}" if 2 * tp + fp + fn else "F1       : N/A")
    print()

if __name__ == "__main__":
    main()
