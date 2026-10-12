#!/usr/bin/env python3

import argparse
import csv
import json
from collections import Counter
from pathlib import Path

def parse_args():
    parser = argparse.ArgumentParser(description="Match Suricata eve.json alerts with ground truth from CSV flows (test rules).")

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

def to_int(val):
    try:
        return int(float(str(val).strip()))
    except (ValueError, TypeError):
        return None


def read_ground_truth(paths):
    groups = {}
    total_rows = 0
    invalid = 0

    columns = {
        "Src IP",
        "Src Port",
        "Dst IP",
        "Dst Port",
        "Protocol",
        "Label",
    }

    for path in paths:
        with open(path, newline="", encoding="cp1252", errors="replace") as file:
            reader = csv.reader(file)
            header = [name.strip() for name in next(reader, [])]

            index = {}
            for name in columns:
                if name not in header:
                    raise ValueError(f"Missing required CSV column: {name}")

                index[name] = header.index(name)

            for row in reader:
                total_rows += 1

                if len(row) < len(header):
                    invalid += 1
                    continue

                src_port = to_int(row[index["Src Port"]])
                dst_port = to_int(row[index["Dst Port"]])
                protocol = to_int(row[index["Protocol"]])
                label = row[index["Label"]].strip().upper()

                if (
                    src_port is None
                    or dst_port is None
                    or protocol is None
                    or not label
                ):
                    invalid += 1
                    continue

                key = (
                    row[index["Src IP"]].strip(),
                    src_port,
                    row[index["Dst IP"]].strip(),
                    dst_port,
                    protocol,
                )

                if key not in groups:
                    groups[key] = {
                        "label": label,
                        "ambiguous": False,
                    }

                group = groups[key]

                if label != group["label"]:
                    group["ambiguous"] = True

    lookup = {}
    ambiguous = 0

    for key, group in groups.items():
        if group["ambiguous"]:
            ambiguous += 1
            continue

        lookup[key] = {
            "label": group["label"],
        }

    return lookup, total_rows, invalid, len(groups), ambiguous

def read_eve(path, lookup, sid_filter=None):
    alert_5tuples = {}
    signatures = Counter()

    total_alerts = 0
    excluded_sid = 0
    malformed = 0

    direct_matches = 0
    reverse_matches = 0

    alerts_without_5tuple = 0

    proto_numbers = {"tcp": 6, "udp": 17, "icmp": 1}

    with open(path, "r", encoding="utf-8", errors="replace") as file:
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

            total_alerts += 1

            signature = alert.get("signature", "UNKNOWN")
            signatures[signature] += 1

            proto_num = proto_numbers.get(str(event.get("proto", "")).lower())
            if proto_num is None:
                alerts_without_5tuple += 1
                continue

            src_ip = event.get("src_ip")
            src_port = event.get("src_port")
            dst_ip = event.get("dest_ip")
            dst_port = event.get("dest_port")

            if None in (src_ip, src_port, dst_ip, dst_port):
                alerts_without_5tuple += 1
                continue

            try:
                src_port = int(src_port)
                dst_port = int(dst_port)
            except (ValueError, TypeError):
                alerts_without_5tuple += 1
                continue

            direct_key = (str(src_ip), src_port, str(dst_ip), dst_port, proto_num)
            reverse_key = (str(dst_ip), dst_port, str(src_ip), src_port, proto_num)

            if direct_key in lookup:
                key = direct_key
                direct_matches += 1
            elif reverse_key in lookup:
                key = reverse_key
                reverse_matches += 1
            else:
                continue

            alert_5tuples.setdefault(key, Counter())[sid] += 1

    return {
        "alert_5tuples": alert_5tuples,
        "signatures": signatures,
        "total_alerts": total_alerts,
        "excluded_sid": excluded_sid,
        "malformed": malformed,
        "alerts_without_5tuple": alerts_without_5tuple,
        "direct_matches": direct_matches,
        "reverse_matches": reverse_matches,
    }

def evaluate(lookup, eve_data):
    alert_5tuples = eve_data["alert_5tuples"]

    tp = fn = fp = tn = 0

    for key, row in lookup.items():
        label = row["label"]
        attack = label != "BENIGN"
        detected = key in alert_5tuples

        if detected and attack:
            tp += 1
        elif detected and not attack:
            fp += 1
        elif not detected and attack:
            fn += 1
        elif not detected and not attack:
            tn += 1

    return tp, fn, fp, tn

def main():
    args = parse_args()

    print("Starting Suricata alert evaluation...")
    print(f"EVE file : {args.eve}")
    print(f"CSV file : {[str(p) for p in args.csv]}")
    print(f"SID      : {'all' if args.sid is None else args.sid}")

    print("Reading csv ground truth...")

    lookup, total_rows, invalid, unique, ambiguous_5tuples = read_ground_truth(args.csv)
    labels = Counter("benign" if row["label"] == "BENIGN" else "attack" for row in lookup.values())
    print(f"CSV rows                 : {total_rows:,}")
    print(f"Unique 5-tuples          : {unique:,}")
    print(f"Valid records            : {len(lookup):,}")
    print(f"Attack records           : {labels['attack']:,}")
    print(f"Benign records           : {labels['benign']:,}")
    print(f"Invalid records          : {invalid:,}")
    print(f"Ambiguous 5-tuples       : {ambiguous_5tuples:,}")
    print()

    print("Reading Suricata alerts...")

    eve_data = read_eve(args.eve, lookup, args.sid)
    print(f"Total alerts             : {eve_data['total_alerts']:,}")
    print(f"Alerts excluded by SID   : {eve_data['excluded_sid']:,}")
    print(f"Malformed JSON lines     : {eve_data['malformed']:,}")
    print(f"Alerts without 5-tuple   : {eve_data['alerts_without_5tuple']:,}")
    print(f"Direct alert matches     : {eve_data['direct_matches']:,}")
    print(f"Reverse alert matches    : {eve_data['reverse_matches']:,}")
    print(f"Detected 5-tuples        : {len(eve_data['alert_5tuples']):,}")
    print()

    if eve_data["signatures"]:
        print("Evaluated signatures:")
        for signature, count in eve_data["signatures"].most_common():
            print(f"  {count:6,}  {signature}")
        print()

    print("Computing evaluation...")
    tp, fn, fp, tn = evaluate(lookup, eve_data)
    total = tp + fn + fp + tn

    print("Metrics:")
    print(f"TP                       : {tp:,}")
    print(f"FN                       : {fn:,}")
    print(f"FP                       : {fp:,}")
    print(f"TN                       : {tn:,}")
    print(f"Total records            : {total:,}")
    print()

    print(f"Recall     : {tp / (tp + fn):.4%}" if tp + fn else "Recall     : N/A")
    print(f"Precision  : {tp / (tp + fp):.4%}" if tp + fp else "Precision  : N/A")
    print(f"FPR        : {fp / (fp + tn):.4%}" if fp + tn else "FPR        : N/A")
    print(f"TNR        : {tn / (tn + fp):.4%}" if tn + fp else "TNR        : N/A")
    print(f"Accuracy   : {(tp + tn) / total:.4%}" if total else "Accuracy  : N/A")
    print(f"F1         : {2 * tp / (2 * tp + fp + fn):.4%}" if 2 * tp + fp + fn else "F1         : N/A")
    print()

if __name__ == "__main__":
    main()
