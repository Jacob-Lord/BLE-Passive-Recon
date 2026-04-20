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

Core pipeline:
- `main.py` — top-level CLI with subcommands
- `advertisement_parser.py` — normalizes BLE advertisement data into a consistent record schema
- `identity_resolution.py` — clusters observations into probable device entities and adds best-effort identity hints
- `feature_extraction.py` — computes time-windowed features per cluster
- `scoring_engine.py` — assigns explainable exposure scores
- `report_cli.py` — prints ranked CLI reports from scored output

Evaluation and analysis:
- `synthetic_trace_generator.py` — generates synthetic BLE observation traces with ground truth
- `evaluate_clustering.py` — evaluates clustering quality (precision/recall/F1, false merges, false splits)
- `inventory_evaluation.py` — evaluates detection recall and time-to-first-seen in controlled trials
- `coverage_at_n.py` — evaluates Coverage@N for exposure prioritization
- `spearman_rank_stability.py` — evaluates ranking stability across repeated captures
- `evaluate_all.py` — runs multiple evaluation stages together
- `plot_clusters.py` — generates cluster timeline and score-over-time plots

## Requirements

- Python 3.11+
- Windows 11 for BLE capture in the current implementation
- BLE-capable adapter
- `bleak` for capture

Optional:
- `matplotlib` for plotting

Suggested Python packages:

```bash
pip install bleak matplotlib
```

## Installation

Clone the repository and enter the project directory:

```bash
git clone https://github.com/<your-username>/<your-repo-name>.git
cd <your-repo-name>
```

Install dependencies:

```bash
pip install bleak matplotlib
```

## Data Format

The pipeline uses **JSONL** (one JSON object per line) for intermediate files.

Typical flow:

- raw capture: `ble_capture.jsonl`
- resolved identities: `ble_capture_resolved.jsonl`
- extracted features: `ble_features.jsonl`
- scored results: `ble_scores.jsonl`

## Usage

### 1. Capture BLE advertisements

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

### 2. Run identity resolution

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

### 3. Extract features

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

### 4. Score exposure

This step generates explainable exposure scores:

```bash
python main.py score outputs/ble_features.jsonl outputs/ble_scores.jsonl --print-top 10
```

### 5. Generate a report

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

### 6. Run the full post-capture pipeline

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

## Evaluation

This repository includes scripts to evaluate the system against four broad goals:

1. **Inventory quality**  
   Detection recall at fixed windows (for example 60s, 300s, 900s) and median time-to-first-seen.

2. **Identity resolution quality**  
   Pairwise precision/recall/F1 plus false merges and false splits using synthetic traces with ground truth.

3. **Exposure prioritization quality**  
   Coverage@N and rank stability across repeated captures.

4. **Practicality**  
   Storage growth rate and scoring latency.

### Controlled inventory evaluation

For a real controlled trial, create a manifest describing the known devices you intentionally placed in range and how to recognize them.

Example manifest:

```json
{
  "devices": [
    {
      "device_id": "jl_rest_device",
      "introduced_offset_seconds": 0,
      "match": {
        "local_name_contains": "Jl Rest",
        "service_uuids_any": ["0000180a-0000-1000-8000-00805f9b34fb"]
      }
    },
    {
      "device_id": "v_7615_device",
      "introduced_offset_seconds": 30,
      "match": {
        "local_name": "V-7615",
        "service_uuids_any": ["4a0246d9-f0fa-4046-8dfd-d249fafd17d7"],
        "manufacturer_company_ids_any": [37383]
      }
    }
  ]
}
```

Run inventory evaluation:

```bash
python inventory_evaluation.py captures/ble_capture.jsonl manifest.json --windows 60 300 900
```

Optional JSON output:

```bash
python inventory_evaluation.py captures/ble_capture.jsonl manifest.json --windows 60 300 900 --output-json inventory_metrics.json
```

### Synthetic clustering evaluation

Generate a synthetic capture with known ground truth:

```bash
python synthetic_trace_generator.py synthetic_capture.jsonl --manifest synthetic_manifest.json
```

Run the normal pipeline on that file:

```bash
python main.py run-all synthetic_capture.jsonl --out-dir outputs --print-top 10
```

Evaluate clustering quality:

```bash
python evaluate_clustering.py outputs/ble_capture_resolved.jsonl --output-json clustering_metrics.json
```

### Coverage@N evaluation

Evaluate how many high-exposure devices appear in the top-ranked results:

```bash
python coverage_at_n.py outputs/ble_scores.jsonl --ns 5 10 20 --output-json coverage_metrics.json
```

By default, this uses `high_exposure_indicator` as the baseline set. You can override that field:

```bash
python coverage_at_n.py outputs/ble_scores.jsonl --baseline-field expected_high_exposure
```

### Spearman rank stability

Compare rankings from two repeated captures of the same environment:

```bash
python spearman_rank_stability.py run1/ble_scores.jsonl run2/ble_scores.jsonl --match-fields probable_device_label --output-json spearman_metrics.json
```

You can combine fields if needed:

```bash
python spearman_rank_stability.py run1/ble_scores.jsonl run2/ble_scores.jsonl --match-fields probable_device_label probable_device_type
```

### Combined evaluation

Run multiple evaluation stages together:

```bash
python evaluate_all.py \
  --capture-input captures/ble_capture.jsonl \
  --inventory-manifest manifest.json \
  --resolved-input outputs/ble_capture_resolved.jsonl \
  --features-input outputs/ble_features.jsonl \
  --scores-input outputs/ble_scores.jsonl \
  --coverage-ns 5 10 20 \
  --output-json all_metrics.json
```

With rank stability included:

```bash
python evaluate_all.py \
  --capture-input run1/ble_capture.jsonl \
  --inventory-manifest manifest.json \
  --resolved-input run1/ble_capture_resolved.jsonl \
  --features-input run1/ble_features.jsonl \
  --scores-input run1/ble_scores.jsonl \
  --spearman-input-a run1/ble_scores.jsonl \
  --spearman-input-b run2/ble_scores.jsonl \
  --spearman-match-fields probable_device_label probable_device_type \
  --output-json all_metrics.json
```

## Visualization

Generate a cluster timeline and score-over-time plots:

```bash
python plot_clusters.py outputs/ble_scores.jsonl --out-dir plots --top-n 10
```

Explicit cluster selection:

```bash
python plot_clusters.py outputs/ble_scores.jsonl --out-dir plots --cluster-ids 3 7 12
```

## Output Interpretation

Each scored record includes:

- `cluster_id` — probable device entity ID
- `probable_device_label` — best-effort label derived from cluster evidence
- `probable_device_type` — best-effort device type inferred from names/UUIDs/manufacturer signals
- `identity_confidence` — confidence in the best-effort identity hint
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
- A local name or UUID can help label a device, but it is not a guaranteed unique identifier.
- This project is intended for passive measurement and exposure assessment only.

## Safe Use

Use this project only in environments where you have authorization to collect BLE advertising data. Do not use it to interfere with devices, initiate unauthorized connections, or attempt exploitation.

## Future Improvements

- SQLite-backed storage and query workflows
- richer UUID/service mapping
- configurable scoring weights
- improved address-rotation handling
- optional Linux/BlueZ capture backend
- stronger automated evaluation dashboards
