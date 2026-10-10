#!/usr/bin/env bash
set -uo pipefail

DATASET_DIR="datasets"

total=0
success=0
failed=0
skipped=0
pcap_count=0
csv_count=0

echo "WARNING: This script may extract at least 100 GB of data."
echo "Make sure you have enough free disk space."

read -r -p "Do you want to continue? [y/N]: " approval

case "${approval,,}" in
    y|yes)
        echo "Extraction approved. Starting..."
        ;;
    *)
        echo "Extraction cancelled. No files were extracted."
        exit 0
        ;;
esac

command -v 7z >/dev/null 2>&1 || {
    echo "ERROR: 7z is not installed."
    exit 1
}

while IFS= read -r -d '' archive; do
    file="${archive%.7z}"
    ((total += 1))

    case "${file,,}" in
        *.pcap|*.pcapng|*.cap)
            type="PCAP"
            ((pcap_count += 1))
            ;;
        *.csv)
            type="CSV"
            ((csv_count += 1))
            ;;
        *)
            continue
            ;;
    esac

    if [[ -f "$file" ]]; then
        echo "SKIP [$type] File already exists: $file"
        ((skipped += 1))
        continue
    fi

    echo
    echo "[$total] Extracting [$type]: $archive"

    if 7z e "$archive" "-o$(dirname "$file")" -y >/dev/null; then
        if [[ -f "$file" ]]; then
            echo "OK Extracted [$type]: $file"
            ((success += 1))
        else
            echo "ERROR Expected file was not created: $file"
            ((failed += 1))
        fi
    else
        echo "ERROR Extraction failed: $archive"
        ((failed += 1))
    fi

done < <(
    find "$DATASET_DIR" -type f \
        \( -iname '*.pcap.7z' \
           -o -iname '*.pcapng.7z' \
           -o -iname '*.cap.7z' \
           -o -iname '*.csv.7z' \) \
        -print0
)

echo
echo "Summary:"
echo "Archives found:       $total"
echo "PCAP archives:        $pcap_count"
echo "CSV archives:         $csv_count"
echo "Successfully extracted: $success"
echo "Skipped:              $skipped"
echo "Errors:               $failed"
