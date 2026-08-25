import csv
import os
import sys


EXPECTED_HEADERS = [
    "time", "device_name", "device_type", "location",
    "temperature_c", "humidity", "object_temperature",
    "ml_prediction", "anomaly_status", "risk_score",
    "risk_level", "action", "attack_status"
]


def normalize_row(row):
    # If row has exactly expected length, return as-is
    if len(row) == len(EXPECTED_HEADERS):
        return row

    # If row is longer, take first N and merge extras into the last field
    if len(row) > len(EXPECTED_HEADERS):
        base = row[: len(EXPECTED_HEADERS) - 1]
        tail = row[len(EXPECTED_HEADERS) - 1 :]
        base.append(" | ".join(tail))
        return base

    # If row is shorter, pad with empty strings
    if len(row) < len(EXPECTED_HEADERS):
        padded = row + [""] * (len(EXPECTED_HEADERS) - len(row))
        return padded


def main(path, inplace=False):
    if not os.path.exists(path):
        print(f"File not found: {path}")
        return 1

    out_path = path if inplace else path.replace(".csv", "_fixed.csv")
    backup_path = path + ".bak"

    # Make a backup when doing in-place replace
    if inplace:
        if not os.path.exists(backup_path):
            os.rename(path, backup_path)
            # restore original variable for reading
            input_path = backup_path
        else:
            input_path = path
    else:
        input_path = path

    with open(input_path, "r", newline="", encoding="utf-8") as infile, \
            open(out_path, "w", newline="", encoding="utf-8") as outfile:
        reader = csv.reader(infile)
        writer = csv.writer(outfile)

        writer.writerow(EXPECTED_HEADERS)

        for row in reader:
            # skip empty rows
            if not row or all((c is None or str(c).strip() == "") for c in row):
                continue

            normalized = normalize_row(row)
            writer.writerow(normalized)

    print(f"Wrote cleaned file: {out_path}")
    if inplace:
        print(f"Backup of original at: {backup_path}")

    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scripts/clean_logs.py <path/to/logs.csv> [--inplace]")
        sys.exit(1)

    path = sys.argv[1]
    inplace_flag = "--inplace" in sys.argv
    sys.exit(main(path, inplace=inplace_flag))
