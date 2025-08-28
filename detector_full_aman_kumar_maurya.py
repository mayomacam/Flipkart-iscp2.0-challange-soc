import csv
import json
import re
import sys

# Secret PII regex
pii_secret = {
    "phone": re.compile(r"^\d{10}$"),
    "aadhar": re.compile(r"^\d{12}$"),
    "passport": re.compile(r"^[A-Z][0-9]{7}$", re.IGNORECASE),
    "upi_id": re.compile(r".+@.+")
}

# Weak PII = only PII when combined with others
weak_pii = ["name", "email", "address", "ip_address", "device_id"]

# False positives to skip
false_pii = [
    "first_name", "last_name", "city", "state", "pin_code",
    "order_id", "transaction_id", "product_description"
]

def masking_value(key, value):
    key_l = key.lower()
    if key_l == "phone" and len(value) == 10:
        return value[:2] + "XXXXXX" + value[-2:]
    elif key_l == "aadhar" and len(value) == 12:
        return value[:4] + "XXXXXXXX" + value[-2:]
    elif key_l == "passport":
        return value[0] + "XXXXXXX"
    elif "upi" in key_l:
        if "@" in value:
            user, domain = value.split("@")
            return user[:2] + "XXX@" + domain
        return "[REDACTED_UPI]"
    elif "email" in key_l:
        if "@" in value:
            user, domain = value.split("@")
            return user[:2] + "XXX@" + domain
        return "[REDACTED_EMAIL]"
    elif "name" in key_l:
        return " ".join([p[0] + "XXX" for p in value.split()])
    elif "address" in key_l:
        return "[REDACTED_ADDRESS]"
    elif "ip" in key_l:
        return "[REDACTED_IP]"
    elif "device" in key_l:
        return "[REDACTED_DEVICE]"
    else:
        return "[REDACTED_PII]"

def classify_pii(data):
    try:
        record = json.loads(data)
    except:
        return data, "Invalid JSON"

    secret_hit = []
    weak_hit = []

    # First pass: identify secret and weak PII
    for field, value in record.items():
        field_l = field.lower()
        val = str(value)

        if field_l in false_pii:
            continue

        # Secret PII
        if field_l in pii_secret and pii_secret[field_l].match(val):
            secret_hit.append(field)

        # Weak PII
        elif field_l in weak_pii:
            weak_hit.append(field)

    # Decision rules
    if secret_hit:  # Any secret PII → always PII
        for f in secret_hit + weak_hit:
            record[f] = masking_value(f, str(record[f]))
        return json.dumps(record), "True"
    elif len(weak_hit) >= 2:  # weak PII
        for f in weak_hit:
            record[f] = masking_value(f, str(record[f]))
        return json.dumps(record), "True"
    else:
        return json.dumps(record), "False"

# File processing
input_file = sys.argv[1]  # input CSV path
output_file = "redacted_output_candidate_aman_kumar_maurya.csv"

with open(input_file, "r", encoding="utf-8") as infile, open(output_file, "w", encoding="utf-8", newline="") as outfile:
    reader = csv.DictReader(infile)
    writer = csv.DictWriter(outfile, fieldnames=["record_id", "redacted_data_json", "is_pii"])
    writer.writeheader()

    for row in reader:
        new_json, pii_flag = classify_pii(row["data_json"])
        writer.writerow({
            "record_id": row.get("record_id", ""),
            "redacted_data_json": new_json,
            "is_pii": pii_flag
        })

print(f"✅ Redaction complete. Output saved to {output_file}")
