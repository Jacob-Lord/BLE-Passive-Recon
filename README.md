# BLE-Passive-Recon
Passive Bluetooth Low Energy (BLE) reconnaissance sensor that builds a time-aware inventory from advertising-only captures and produces an explainable exposure/risk score using advertised services, connectability/discoverability posture, and temporal stability signals (no pairing, no connections, no GATT).


## Scope

This project is **advertising-only**:
- no pairing
- no BLE connections
- no GATT enumeration
- no active exploitation

The pipeline is designed to answer:

- What BLE devices are present?
- Which devices appear repeatedly over time?
- Which devices expose stronger passive-identification or targeting signals?
- Which advertised services may indicate higher-impact device roles?

## Pipeline

The end-to-end workflow is:

```text
capture -> advertisement_parser -> identity_resolution -> feature_extraction -> scoring_engine -> report_cli
```

## Repository Files

- `main.py` — top-level CLI with subcommands
- `advertisement_parser.py` — normalizes BLE advertisement data into a consistent record schema
- `identity_resolution.py` — clusters observations into probable device entities
- `feature_extraction.py` — computes time-windowed features per cluster
- `scoring_engine.py` — assigns explainable exposure scores
- `report_cli.py` — prints ranked CLI reports from scored output

## Requirements

- Python 3.11+
- Windows 11 for BLE capture in the current implementation
- BLE-capable adapter
- `bleak` for capture

Suggested Python packages:

```bash
pip install bleak
```

## Installation

Clone the repository and enter the project directory:

```bash
git clone https://github.com/<your-username>/<your-repo-name>.git
cd <your-repo-name>
```

Install dependencies:

```bash
pip install bleak
```

## Data Format

The pipeline uses **JSONL** (one JSON object per line) for intermediate files.

Typical flow:

- raw capture: `ble_capture.jsonl`
- resolved identities: `ble_capture_resolved.jsonl`
- extracted features: `ble_features.jsonl`
- scored results: `ble_scores.jsonl`

## Usage

## 1. Capture BLE advertisements

Capture advertisements for 5 minutes:

```bash
python main.py capture captures/ble_capture.jsonl --duration 300
```

Run until interrupted:

```bash
python main.py capture captures/ble_capture.jsonl
```

Passive scan mode is the default. To use active scanning:

```bash
python main.py capture captures/ble_capture.jsonl --scanning-mode active
```

Suppress per-advertisement console output:

```bash
python main.py capture captures/ble_capture.jsonl --duration 300 --quiet
```

## 2. Run identity resolution

This step assigns observations to probable device clusters:

```bash
python main.py resolve captures/ble_capture.jsonl outputs/ble_capture_resolved.jsonl
```

Optional tuning:

```bash
python main.py resolve captures/ble_capture.jsonl outputs/ble_capture_resolved.jsonl \
  --max-gap-seconds 600 \
  --min-link-score 0.68
```

## 3. Extract features

This step computes time-windowed features for each cluster:

```bash
python main.py extract outputs/ble_capture_resolved.jsonl outputs/ble_features.jsonl --window-seconds 300
```

Optional top-k retention for UUID/company summaries:

```bash
python main.py extract outputs/ble_capture_resolved.jsonl outputs/ble_features.jsonl \
  --window-seconds 300 \
  --top-k 5
```

## 4. Score exposure

This step generates explainable exposure scores:

```bash
python main.py score outputs/ble_features.jsonl outputs/ble_scores.jsonl --print-top 10
```

## 5. Generate a report

Print a ranked report from the scored output:

```bash
python main.py report outputs/ble_scores.jsonl --top 10
```

Only show high-tier devices:

```bash
python main.py report outputs/ble_scores.jsonl --tier high --top 20
```

Show full history for a specific cluster:

```bash
python main.py report outputs/ble_scores.jsonl --cluster-id 7
```

Export the latest ranked view to JSON:

```bash
python main.py report outputs/ble_scores.jsonl --export-json latest_report.json
```

## 6. Run the full post-capture pipeline

Process an existing capture file through resolve -> extract -> score:

```bash
python main.py run-all captures/ble_capture.jsonl --out-dir outputs --print-top 10
```

## Example Workflow

```bash
python main.py capture captures/ble_capture.jsonl --duration 300
python main.py run-all captures/ble_capture.jsonl --out-dir outputs --print-top 10
python main.py report outputs/ble_scores.jsonl --top 10
```

## Output Interpretation

Each scored record includes:

- `cluster_id` — probable device entity ID
- `exposure_score` — overall 0–100 score
- `confidence_score` — confidence in the score based on observation support
- `exposure_tier` — low / medium / high
- `high_exposure_indicator` — simple baseline flag
- `score_components` — component scores:
  - attack surface
  - identifiability
  - trackability
  - service sensitivity
- `score_drivers` — top features contributing to the score

## Notes and Limitations

- Current capture uses the Windows BLE stack through `bleak`.
- Some low-level BLE fields may not be available through the high-level API.
- Identity resolution is **best-effort** and probabilistic.
- BLE advertisements are unauthenticated and can be spoofed.
- This project is intended for passive measurement and exposure assessment only.

## Safe Use

Use this project only in environments where you have authorization to collect BLE advertising data. Do not use it to interfere with devices, initiate unauthorized connections, or attempt exploitation.

## Future Improvements

- SQLite-backed storage and query workflows
- richer UUID/service mapping
- configurable scoring weights
- improved address-rotation handling
- optional Linux/BlueZ capture backend

