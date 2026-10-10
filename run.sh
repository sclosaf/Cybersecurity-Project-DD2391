#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RULES="$PROJECT_DIR/custom.rules"

TRAIN_PCAP="$PROJECT_DIR/datasets/pcap/training"
TRAIN_CSV="$PROJECT_DIR/datasets/csv/training"

TEST_PCAP="$PROJECT_DIR/datasets/pcap/test"
TEST_CSV="$PROJECT_DIR/datasets/csv/test"

SURICATA_DIR="$PROJECT_DIR/suricata"

declare -A ATTACKS=(
    [1]="Backdoor-attack"
    [2]="DDoS-HTTP-Flood-attacks"
    [3]="DDoS-ICMP-Flood-attacks"
    [4]="DDoS-TCP-SYN-Flood-attacks"
    [5]="DDoS-UDP-Flood-attacks"
    [6]="MITM-attack"
    [7]="OS-Fingerprinting-attack"
    [8]="Password-attacks"
    [9]="Port-Scanning-attack"
    [10]="Ransomware-attack"
    [11]="SQL-injection-attack"
    [12]="Uploading-attack"
    [13]="Vulnerability-scanner-attack"
    [14]="XSS-attacks"
)

MODE=""
NUMBER=""

usage()
{
    echo "Usage:"
    echo "  $0 -m 0 -n N    Training: process the selected attack and evaluate its CSV"
    echo "  $0 -m 1         Test: process all test PCAPs and evaluate all 4 CSVs"
    echo
    echo "Options:"
    echo "  -m MODE         0 = training, 1 = test"
    echo "  -n NUMBER       Attack index (required with -m 0)"
    echo "  -h              Display this help message"
    echo
    echo "Available training attacks:"

    for key in $(printf '%s\n' "${!ATTACKS[@]}" | sort -n); do
        echo "  $key) ${ATTACKS[$key]}"
    done

    exit 1
}

run_suricata()
{
    local pcap="$1"
    local output_dir="$2"

    sudo mkdir -p "$output_dir"
    sudo chown -R suricata:suricata "$output_dir"

    echo
    echo "Processing PCAP: $(basename "$pcap")"

    sudo suricata \
        -r "$pcap" \
        -S "$RULES" \
        -l "$output_dir" \
        -k none

    if [[ ! -f "$output_dir/eve.json" ]]; then
        echo "ERROR: Suricata did not generate $output_dir/eve.json" >&2
        exit 1
    fi

    sudo chown -R "$USER":"$(id -gn)" "$output_dir"
}

main()
{
    while getopts ":m:n:h" opt; do
        case "$opt" in
            m) MODE="$OPTARG" ;;
            n) NUMBER="$OPTARG" ;;
            h) usage ;;
            *) usage ;;
        esac
    done

    if [[ "$MODE" != "0" && "$MODE" != "1" ]]; then
        echo "ERROR: Invalid or missing mode. Use -m 0 or -m 1." >&2
        usage
    fi

    if [[ "$MODE" == "0" ]]; then
        if [[ ! "$NUMBER" =~ ^[0-9]+$ ]] ||
           [[ -z "${ATTACKS[$NUMBER]+present}" ]]; then
            echo "ERROR: Invalid attack number '${NUMBER:-<missing>}'." >&2
            usage
        fi
    elif [[ -n "$NUMBER" ]]; then
        echo "ERROR: The -n option is only available in training mode." >&2
        exit 1
    fi

    for cmd in suricata python3; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo "ERROR: Required command not found: $cmd" >&2
            exit 1
        fi
    done

    for file in \
        "$RULES" \
        "$PROJECT_DIR/evaluate_training.py" \
        "$PROJECT_DIR/evaluate_test.py"; do
        if [[ ! -f "$file" ]]; then
            echo "ERROR: Required file not found: $file" >&2
            exit 1
        fi
    done

    if [[ "$MODE" == "0" ]]; then
        if [[ ! -d "$TRAIN_PCAP" || ! -d "$TRAIN_CSV" ]]; then
            echo "ERROR: Training dataset directories not found." >&2
            exit 1
        fi
    else
        if [[ ! -d "$TEST_PCAP" || ! -d "$TEST_CSV" ]]; then
            echo "ERROR: Test dataset directories not found." >&2
            exit 1
        fi
    fi

    if [[ -e "$SURICATA_DIR" ]]; then
        sudo rm -rf -- "$SURICATA_DIR"
    fi

    mkdir -p "$SURICATA_DIR"

    if [[ "$MODE" == "0" ]]; then
        NAME="${ATTACKS[$NUMBER]}"
        PCAP="$TRAIN_PCAP/$NAME.pcap"
        CSV="$TRAIN_CSV/$NAME.csv"
        OUT="$SURICATA_DIR/training/$NAME"

        if [[ ! -f "$PCAP" ]]; then
            echo "ERROR: PCAP not found: $PCAP" >&2
            exit 1
        fi

        if [[ ! -f "$CSV" ]]; then
            echo "ERROR: Matching CSV not found: $CSV" >&2
            exit 1
        fi

        run_suricata "$PCAP" "$OUT"

        python3 "$PROJECT_DIR/evaluate_training.py" \
            --eve "$OUT/eve.json" \
            --csv "$CSV" \
            --pcap "$PCAP"

    else
        shopt -s nullglob
        pcaps=("$TEST_PCAP"/*.pcap)
        csvs=("$TEST_CSV"/*.csv)
        shopt -u nullglob

        if [[ "${#pcaps[@]}" -eq 0 ]]; then
            echo "ERROR: No test PCAPs found in $TEST_PCAP" >&2
            exit 1
        fi

        if [[ "${#csvs[@]}" -ne 4 ]]; then
            echo "ERROR: Expected exactly 4 test CSV files, found ${#csvs[@]} in $TEST_CSV" >&2
            exit 1
        fi

        OUT="$SURICATA_DIR/test"
        EVE_DIR="$OUT/individual_eve"
        MERGED_EVE="$OUT/eve.json"

        mkdir -p "$EVE_DIR"
        : > "$MERGED_EVE"

        for pcap in "${pcaps[@]}"; do
            base="$(basename "$pcap" .pcap)"
            pcap_out="$EVE_DIR/$base"

            run_suricata "$pcap" "$pcap_out"

            cat "$pcap_out/eve.json" >> "$MERGED_EVE"
        done

        printf '  %s\n' "${csvs[@]}"

        python3 "$PROJECT_DIR/evaluate_test.py" \
            --eve "$MERGED_EVE" \
            --csv "${csvs[@]}"

    fi
}

main "$@"
