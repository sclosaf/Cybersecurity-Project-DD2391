#!/usr/bin/env python3

import argparse
import csv
import json
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

SRC_IP = 0
SRC_PORT = 1
DST_IP = 2
DST_PORT = 3
PROTOCOL = 4
START_TIME = 28
END_TIME = 29
LABEL = 48

def parse_args():

    parser = argparse.ArgumentParser(description="Evaluate Suricata alerts against csv ground truth (test rules).")

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
        nargs="+",
        type=Path,
        help="Path to ground-truth csvs"
    )

    parser.add_argument(
        "-s",
        "--sid",
        type=int,
        required=False,
        help="Suricata SID to evaluate"
    )

    return parser.parse_args()

def normalize(val):
    return str(val or "").strip().lower()

def normalize_protocol(val):
    val = normalize(val)

    return {
        "6": "tcp",
        "17": "udp",
        "1": "icmp"
    }.get(val, val)

def parse_timestamp(val):
    val = str(val or "").strip()
    if not val:
        return None

    try:
        return float(val)
    except ValueError:
        pass

    try:
        dt = datetime.fromisoformat(val.replace("Z", "+00:00"))

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        return dt.timestamp()
    except (ValueError, OverflowError, OSError):
        return None

def read_ground_truth(paths):
    records = []
    labels = Counter()
    invalid = 0
    ignored = 0

    for path in paths:
        with open(path, newline="", encoding="utf-8-sig", errors="replace") as file:
            reader = csv.reader(file)

            for line, row in enumerate(reader, start=1):
                if len(row) <= LABEL:
                       invalid += 1
                       continue

                try:
                    label = int(float(row[LABEL].strip()))
                    src_port = int(float(row[SRC_PORT]))
                    dst_port = int(float(row[DST_PORT]))
                except (ValueError, TypeError, IndexError):
                    invalid += 1
                    continue

                if label not in (0, 1):
                    ignored += 1
                    continue

                src_ip = normalize(row[SRC_IP])
                dst_ip = normalize(row[DST_IP])
                proto = normalize(row[PROTOCOL])
                start = parse_timestamp(row[START_TIME])
                end = parse_timestamp(row[END_TIME])

                if(not src_ip or not dst_ip or src_port is None or dst_port is None or not proto or start is None or end is None):
                    invalid += 1
                    continue

                if end < start :
                    invalid += 1
                    continue

                records.append({
                    "record_id": len(records) + 1,
                    "source_file": str(path),
                    "source_line": line,
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "proto": proto,
                    "start": start,
                    "end": end,
                    "label": label,
                })

                labels[label] += 1

    return records, labels, invalid, ignored

def read_eve(path, sid_filter=None):
    alerts = []
    malformed = 0
    missing_timestamp = 0
    excluded_sid = 0
    signatures = Counter()
    seen = set()

    with open(path, encoding="utf-8", errors="replace") as file:
        for line in file:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                malformed += 1
                continue

            if event.get("event_type") != "alert":
                continue

            alert = event.get("alert") or {}
            sid = alert.get("signature_id")

            if sid_filter is not None and sid != sid_filter:
                excluded_sid += 1
                continue

            timestamp = parse_timestamp(event.get("timestamp"))

            if timestamp is None:
                missing_timestamp += 1
                continue

            alert = {
                    "timestamp": timestamp,
                    "flow_id": event.get("flow_id"),
                    "sid": sid,
                    "signature": str(alert.get("signature", "UNKNOWN")),
                    "src_ip": normalize(event.get("src_ip")),
                    "src_port": int(event.get("src_port")),
                    "dst_ip": normalize(event.get("dest_ip")),
                    "dst_port": int(event.get("dest_port")),
                    "proto": normalize_protocol(event.get("proto"))
            }

            key = (sid, alert["proto"], alert["src_ip"], alert["src_port"], alert["dst_ip"], alert["dst_port"], timestamp, alert["signature"],)

            if key in seen:
                continue

            seen.add(key)

            alert["alert_id"] = len(alerts) + 1
            alerts.append(alert)
            signatures[alert["signature"]] += 1


    stats = {
        "unique_alerts": len(alerts),
        "malformed": malformed,
        "missing_timestamp": missing_timestamp,
        "excluded_sid": excluded_sid,
        "signatures": signatures,
    }

    return alerts, stats

def flow_matches(record, alert):
    if record["proto"] != alert["proto"]:
        return False

    if alert["src_port"] is None or alert["dst_port"] is None:
        return False

    forward = (
        record["src_ip"] == alert["src_ip"]
        and record["dst_ip"] == alert["dst_ip"]
        and record["src_port"] == alert["src_port"]
        and record["dst_port"] == alert["dst_port"]
    )

    reverse = (
        record["src_ip"] == alert["dst_ip"]
        and record["dst_ip"] == alert["src_ip"]
        and record["src_port"] == alert["dst_port"]
        and record["dst_port"] == alert["src_port"]
    )

    if not (forward or reverse):
        return False

    return (record["start"] <= alert["timestamp"] <= record["end"])


def evaluate(records, alerts):
    tp = fn = fp = tn = 0
    matched = set()
    ambiguous = 0

    index = defaultdict(list)

    for alert in alerts:
        forward_key = (
            alert["proto"],
            alert["src_ip"],
            alert["src_port"],
            alert["dst_ip"],
            alert["dst_port"],
        )

        reverse_key = (
            alert["proto"],
            alert["dst_ip"],
            alert["dst_port"],
            alert["src_ip"],
            alert["src_port"],
        )

        index[forward_key].append(alert)
        if reverse_key != forward_key:
            index[reverse_key].append(alert)

    times_index = {}

    for key, items in index.items():
        items.sort(key=lambda a: a["timestamp"])
        times_index[key] = [a["timestamp"] for a in items]

    for record in records:
        forward_key = (
            record["proto"],
            record["src_ip"],
            record["src_port"],
            record["dst_ip"],
            record["dst_port"],
        )

        reverse_key = (
            record["proto"],
            record["dst_ip"],
            record["dst_port"],
            record["src_ip"],
            record["src_port"],
        )

        candidate_alerts = {}

        for key in (forward_key, reverse_key):
            items = index.get(key)
            if not items:
                continue

            times = times_index[key]

            left = bisect_left(times, record["start"])
            right = bisect_right(times, record["end"])

            for alert in items[left:right]:
                candidate_alerts[alert["alert_id"]] = alert

        matches = candidate_alerts.values()
        detected = bool(candidate_alerts)
        attack = record["label"] == 1

        if attack and detected:
            tp += 1
        elif attack and not detected:
            fn += 1
        elif not attack and detected:
            fp += 1
        else:
            tn += 1

        if len(candidate_alerts) > 1:
            ambiguous += 1

        matched.update(candidate_alerts.keys())

    unmatched = [
        alert for alert in alerts
        if alert["alert_id"] not in matched
    ]

    return tp, fn, fp, tn, matched, unmatched, ambiguous

def main():
    args = parse_args()

    print("Starting Suricata alert evaluation...")
    print("Using the following configuration:")
    print(f"EVE file : {args.eve}")
    print(f"CSV file : {args.csv}")
    print(f"SID      : {'all' if args.sid is None else args.sid}")
    print()

    print("Reading ground-truth CSV...")
    records, labels, invalid, ignored = read_ground_truth(args.csv)
    print(f"Valid records            : {len(records):,}")
    print(f"Attack records           : {labels[1]:,}")
    print(f"Benign records           : {labels[0]:,}")
    print(f"Invalid records          : {invalid:,}")
    print(f"Unsupported labels       : {ignored:,}")
    print()

    print("Reading Suricata EVE alerts...")
    alerts, stats = read_eve(args.eve, args.sid)
    print(f"Unique alerts            : {stats['unique_alerts']:,}")
    print(f"Alerts excluded by SID   : {stats['excluded_sid']:,}")
    print(f"Malformed JSON lines     : {stats['malformed']:,}")
    print(f"Alerts without timestamp : {stats['missing_timestamp']:,}")

    if stats["signatures"]:
        print()
        print("Evaluated signatures:")
        for signature, count in stats["signatures"].most_common():
            print(f"  {count:7,}  {signature}")
    print()

    print("Evaluating records...")

    tp, fn, fp, tn, matched, unmatched, ambiguous = evaluate(records, alerts)
    total = tp + fn + fp + tn

    print()
    print("Metrics:")
    print(f"TP                       : {tp:,}")
    print(f"FN                       : {fn:,}")
    print(f"FP                       : {fp:,}")
    print(f"TN                       : {tn:,}")
    print(f"Total records            : {total:,}")
    print(f"Matched alerts           : {len(matched):,}")
    print(f"Unmatched alerts         : {len(unmatched):,}")
    print(f"Multiple matching alerts : {ambiguous:,}")
    print()

    print(f"recall     : {tp / (tp + fn):.4%}" if tp + fn else "recall     : n/a")  # Proportion of actual attack flows correctly detected.
    print(f"precision  : {tp / (tp + fp):.4%}" if tp + fp else "precision  : n/a")  # Proportion of detected attack flows that were actual attacks.
    print(f"fpr        : {fp / (fp + tn):.4%}" if fp + tn else "fpr        : n/a")  # Proportion of benign flows incorrectly classified as attacks.
    print(f"tnr        : {tn / (tn + fp):.4%}" if tn + fp else "tnr        : n/a")  # Proportion of benign flows correctly classified as benign.
    print(f"accuracy   : {(tp + tn) / total:.4%}" if total else "accuracy   : n/a")  # Proportion of all flows correctly classified.

    print(f"f1         : {2 * tp / (2 * tp + fp + fn):.4%}" if 2 * tp + fp + fn else "f1         : n/a")  # Harmonic mean of precision and recall.

    print()

if __name__ == "__main__":
    main()
