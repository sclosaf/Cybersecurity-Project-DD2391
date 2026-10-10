#!/usr/bin/env bash
set -uo pipefail

DATASET_DIR="datasets"
MAX_SIZE=$((90 * 1024 * 1024))

total=0
success=0
failed=0
too_large=0
skipped=0

while IFS= read -r -d '' file; do
    archive="${file}.7z"
    ((total += 1))

    if [[ -f "$archive" ]]; then
        echo "SKIP Existing archive: $archive"
        ((skipped += 1))
        continue
    fi

    echo
    echo "[$total] Compressing: $file"

    if ! 7z a -t7z -mx=5 "$archive" "$file" -bsp1; then
        echo "ERROR Compression failed: $file"
        rm -f "$archive"
        ((failed += 1))
        continue
    fi

    if ! 7z t "$archive" >/dev/null; then
        echo "ERROR Verification failed: $archive"
        rm -f "$archive"
        ((failed += 1))
        continue
    fi

    size=$(stat -c '%s' "$archive")
    human_size=$(du -h "$archive" | cut -f1)

    if (( size >= MAX_SIZE )); then
        echo "LARGE $archive ($human_size)"
        ((too_large += 1))
    else
        echo "OK $archive ($human_size)"
    fi

    ((success += 1))

done < <(
    find "$DATASET_DIR" -type f \
        \( -iname '*.pcap' -o -iname '*.pcapng' -o -iname '*.cap' -o -iname '*.csv' \) \
        -print0
)

echo
echo "Summary:"
echo "Files found:       $total"
echo "Archives created:  $success"
echo "Failed:            $failed"
echo "Archives >= 90MB:  $too_large"
echo "Skipped:           $skipped"
