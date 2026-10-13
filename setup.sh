#!/usr/bin/env bash

# Note: This file was AI-generated and reviewed to ensure proper use.

set -Eeuo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

SETUP="setup"
CIC_ZIP="CICIDS2017_improved.zip"
EDGE_ZIP="edgeiiotset-cyber-security-dataset-of-iot-iiot.zip"

ATTACKS='
Backdoor-attack|Backdoor_attack.csv|Backdoor_attack.pcap
DDoS-HTTP-Flood-attacks|DDoS_HTTP_Flood_attack.csv|DDoS HTTP Flood Attacks.pcap
DDoS-ICMP-Flood-attacks|DDoS_ICMP_Flood_attack.csv|DDoS ICMP Flood Attacks.pcap
DDoS-TCP-SYN-Flood-attacks|DDoS_TCP_SYN_Flood_attack.csv|DDoS TCP SYN Flood Attacks.pcap
DDoS-UDP-Flood-attacks|DDoS_UDP_Flood_attack.csv|DDoS UDP Flood Attacks.pcap
MITM-attack|MITM_attack.csv|MITM (ARP spoofing + DNS) Attack.pcap
OS-Fingerprinting-attack|OS_Fingerprinting_attack.csv|OS Fingerprinting attack.pcap
Password-attacks|Password_attack.csv|Password attacks.pcap
Port-Scanning-attack|Port_Scanning_attack.csv|Port Scanning attack.pcap
Ransomware-attack|Ransomware_attack.csv|Ransomware attack.pcap
SQL-injection-attack|SQL_injection_attack.csv|SQL injection attack.pcap
Uploading-attack|Uploading_attack.csv|Uploading attack.pcap
Vulnerability-scanner-attack|Vulnerability_scanner_attack.csv|Vulnerability scanner attack.pcap
XSS-attacks|XSS_attack.csv|XSS attacks.pcap
'

NORMAL="Distance Flame_Sensor Heart_Rate IR_Receiver Modbus phValue Soil_Moisture Sound_Sensor Temperature_and_Humidity Water_Level"

TESTS='
monday|Monday-WorkingHours.pcap
tuesday|Tuesday-WorkingHours.pcap
wednesday|Wednesday-workingHours.pcap
thursday|Thursday-WorkingHours.pcap
friday|Friday-WorkingHours.pcap
'

find_ci()
{
    find "$SETUP" -maxdepth 1 -type f -iname "$1" -size +0 -print -quit
}

usage()
{
    echo "Usage: $0 [-h]"
    echo
    echo "Extract, rename and place the datasets into datasets/, the layout expected by run.sh."
    echo
    echo "Before running it, create a '$SETUP' directory in the project root containing exactly:"
    echo "  $CIC_ZIP"
    echo "  $EDGE_ZIP"

    while IFS='|' read -r day pcap; do
        [[ -n "$day" ]] || continue
        echo "  $pcap"
    done <<<"$TESTS"

    echo
    echo "Where to download them:"
    echo "  $EDGE_ZIP"
    echo "      https://www.kaggle.com/datasets/mohamedamineferrag/edgeiiotset-cyber-security-dataset-of-iot-iiot/data"
    echo "  $CIC_ZIP (CSV only)"
    echo "      https://intrusion-detection.distrinet-research.be/CNS2022/CICIDS2017.html"
    echo "  monday/tuesday/wednesday/thursday/friday-WorkingHours.pcap (PCAP only)"
    echo "      https://www.unb.ca/cic/datasets/ids-2017.html"
    echo
    echo "The zips are read as they are (do not extract them); the PCAPs must be directly inside $SETUP/."
    echo "Requires: unzip"
    echo
    echo "Options:"
    echo "  -h              Display this help message"
}

plan()
{
    while IFS='|' read -r name csv pcap; do
        [[ -n "$name" ]] || continue
        echo "$ATTACK_DIR/$pcap|pcap|training|$name"
        echo "$ATTACK_DIR/$csv|csv|training|$name"
    done <<<"$ATTACKS"

    for name in $NORMAL; do
        echo "$NORMAL_DIR/$name/$name.pcap|pcap|training|$name"
        echo "$NORMAL_DIR/$name/$name.csv|csv|training|$name"
    done

    while IFS='|' read -r day pcap; do
        [[ -n "$day" ]] || continue
        echo "$(find_ci "$pcap")|pcap|test|$day"
        echo "$(find "$TMP/cic" -type f -name "$day.csv" -print -quit)|csv|test|$day"
    done <<<"$TESTS"
}

while getopts ":h" opt; do
    case "$opt" in
        h) usage; exit 0 ;;
        *) usage >&2; exit 1 ;;
    esac
done

if [[ ! -d "$SETUP" ]]; then
    echo "ERROR: directory '$SETUP' not found." >&2
    echo >&2
    usage >&2
    exit 1
fi

command -v unzip >/dev/null 2>&1 || { echo "ERROR: unzip is not installed." >&2; exit 1; }

required=("$CIC_ZIP" "$EDGE_ZIP")
while IFS='|' read -r day pcap; do
    [[ -n "$day" ]] && required+=("$pcap")
done <<<"$TESTS"

missing=0
for file in "${required[@]}"; do
    if [[ -z "$(find_ci "$file")" ]]; then
        echo "ERROR: missing (or empty) in $SETUP/: $file" >&2
        missing=1
    fi
done
if [[ $missing -ne 0 ]]; then
    echo >&2
    usage >&2
    exit 1
fi

TMP="$(mktemp -d "$SETUP/.extract.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

echo "Extracting $EDGE_ZIP (attack and normal traffic only)..."
unzip -q "$(find_ci "$EDGE_ZIP")" '*Attack traffic/*' '*Normal traffic/*' -d "$TMP/edge"

echo "Extracting $CIC_ZIP..."
unzip -q "$(find_ci "$CIC_ZIP")" -d "$TMP/cic"

ATTACK_DIR="$(find "$TMP/edge" -type d -name 'Attack traffic' -print -quit)"
NORMAL_DIR="$(find "$TMP/edge" -type d -name 'Normal traffic' -print -quit)"

PLAN="$(plan)"

bad=0
while IFS='|' read -r src kind split name; do
    if [[ ! -f "$src" ]]; then
        echo "ERROR: source not found for $split/$name.$kind: ${src:-<none>}" >&2
        bad=1
    fi
done <<<"$PLAN"
[[ $bad -eq 0 ]] || exit 1

count=0
while IFS='|' read -r src kind split name; do
    dest="datasets/$kind/$split/$name.$kind"
    mkdir -p "$(dirname "$dest")"

    if [[ "$src" == "$TMP"/* ]]; then
        mv -f -- "$src" "$dest"
    else
        ln -f -- "$src" "$dest" 2>/dev/null || cp -f -- "$src" "$dest"
    fi

    echo "OK $dest"
    ((count += 1))
done <<<"$PLAN"

echo
echo "Done: $count files placed in datasets/"
