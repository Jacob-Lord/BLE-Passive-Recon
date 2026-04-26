import json
import argparse
from pathlib import Path
from scoring_engine import BLEExposureScoringEngine


def read_jsonl(path: Path):
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def find_latest_row_by_label(rows, label: str):
    matches = [r for r in rows if r.get("probable_device_label") == label]
    if not matches:
        raise ValueError(f"No feature row found for label: {label}")
    return max(matches, key=lambda r: r.get("window_end", ""))


def print_result(name: str, scored: dict):
    print(
        f"{name:24s} "
        f"score={scored['exposure_score']:.2f} "
        f"attack={scored['attack_surface_score']:.2f} "
        f"ident={scored['identifiability_score']:.2f} "
        f"track={scored['trackability_score']:.2f} "
        f"service={scored['service_sensitivity_score']:.2f}"
    )


parser = argparse.ArgumentParser()
parser.add_argument("input", help="Path to ble_features.jsonl")
parser.add_argument("--label", required=True, help="probable_device_label to test")
args = parser.parse_args()

rows = list(read_jsonl(Path(args.input)))
base = find_latest_row_by_label(rows, args.label)

engine = BLEExposureScoringEngine()

variants = []

# baseline
variants.append(("baseline", dict(base)))

# remove connectability/discoverability/scannability
v = dict(base)
v["connectable_fraction"] = 0.0
v["discoverable_fraction"] = 0.0
v["scannable_fraction"] = 0.0
variants.append(("posture_removed", v))

# remove identifying name/label signals
v = dict(base)
v["local_name_present_fraction"] = 0.0
v["local_name_stability"] = 0.0
v["probable_device_label"] = None
v["probable_device_label_stability"] = 0.0
v["identity_confidence"] = 0.0
v["identification_basis"] = []
variants.append(("identity_removed", v))

# remove temporal stability signals
v = dict(base)
v["cluster_presence_fraction_all_windows"] = 0.0
v["dominant_uuid_signature_fraction"] = 0.0
v["dominant_company_signature_fraction"] = 0.0
v["dominant_address_fraction"] = 0.0
variants.append(("temporal_removed", v))

# remove sensitive service surface
v = dict(base)
v["sensitive_service_count"] = 0
v["sensitive_service_categories"] = []
v["unique_service_uuid_count"] = 0
v["top_service_uuids"] = []
variants.append(("service_removed", v))

for name, row in variants:
    scored = engine.score_record(row)
    print_result(name, scored)