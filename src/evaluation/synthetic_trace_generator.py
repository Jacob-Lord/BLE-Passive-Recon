from __future__ import annotations

import argparse
import json
import random
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


BASE_UUID_SUFFIX = "-0000-1000-8000-00805f9b34fb"


def to_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def write_jsonl(path: Path, records: Iterable[Dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, separators=(",", ":")) + "\n")


def normalize_uuid(uuid: str) -> str:
    s = uuid.strip().lower()
    if len(s) == 4:
        return f"0000{s}{BASE_UUID_SUFFIX}"
    if len(s) == 8:
        return f"{s}{BASE_UUID_SUFFIX}"
    return s


def rand_mac(rng: random.Random) -> str:
    return ":".join(f"{rng.randint(0, 255):02x}" for _ in range(6))


def bounded_gaussian_int(rng: random.Random, mean: int, std: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, int(round(rng.gauss(mean, std)))))


@dataclass
class DeviceConfig:
    device_truth_id: str
    scenario_name: str
    addr_type: str
    adv_type: str
    local_name: Optional[str]
    service_uuids: List[str]
    manufacturer_company_id: Optional[int]
    manufacturer_data_prefix: Optional[str]
    service_data_uuid: Optional[str]
    service_data_prefix: Optional[str]
    rssi_mean: int
    rssi_std: int
    interval_seconds: int
    packet_loss: float
    address_rotation_seconds: Optional[int]
    expected_high_exposure: bool
    truth_device_type: str


class SyntheticTraceGenerator:
    def __init__(self, seed: int = 7) -> None:
        self.rng = random.Random(seed)

    def _make_flags(self, discoverable: bool) -> Dict[str, Any]:
        return {
            "raw": 6 if discoverable else 4,
            "hex": "0x06" if discoverable else "0x04",
            "names": [
                "LE General Discoverable Mode",
                "BR/EDR Not Supported",
            ] if discoverable else ["BR/EDR Not Supported"],
            "limited_discoverable": False,
            "general_discoverable": discoverable,
            "br_edr_not_supported": True,
            "simultaneous_le_br_edr_controller": False,
            "simultaneous_le_br_edr_host": False,
        }

    def _manufacturer_data(self, company_id: Optional[int], prefix: Optional[str], seq: int) -> List[Dict[str, Any]]:
        if company_id is None:
            return []
        suffix = f"{seq % 256:02x}{(seq * 3) % 256:02x}"
        payload = (prefix or "aa55") + suffix
        return [{
            "company_id": company_id,
            "company_id_hex": f"0x{company_id:04x}",
            "manufacturer_data_hex": payload,
        }]

    def _service_data(self, uuid: Optional[str], prefix: Optional[str], seq: int) -> List[Dict[str, Any]]:
        if not uuid:
            return []
        payload = (prefix or "10") + f"{seq % 256:02x}"
        return [{
            "uuid": normalize_uuid(uuid),
            "service_data_hex": payload,
        }]

    def _address_for_time(self, base_addr: str, cfg: DeviceConfig, elapsed_seconds: int) -> str:
        if not cfg.address_rotation_seconds:
            return base_addr
        epoch = elapsed_seconds // cfg.address_rotation_seconds
        mac_parts = base_addr.split(":")
        last = int(mac_parts[-1], 16)
        mac_parts[-1] = f"{(last + epoch) % 256:02x}"
        return ":".join(mac_parts)

    def _emit_device(self, cfg: DeviceConfig, start: datetime, duration_seconds: int) -> List[Dict[str, Any]]:
        records: List[Dict[str, Any]] = []
        base_addr = rand_mac(self.rng)
        seq = 0

        for offset in range(0, duration_seconds, cfg.interval_seconds):
            if self.rng.random() < cfg.packet_loss:
                continue

            ts = start + timedelta(seconds=offset)
            addr = self._address_for_time(base_addr, cfg, offset)
            rssi = bounded_gaussian_int(self.rng, cfg.rssi_mean, cfg.rssi_std, -95, -25)

            discoverable = cfg.adv_type in {"ADV_IND", "ADV_SCAN_IND", "ADV_DIRECT_IND"}
            record = {
                "ts": to_iso(ts),
                "rssi": rssi,
                "addr": addr,
                "addr_type": cfg.addr_type,
                "adv_type": cfg.adv_type,
                "payload_hex": None,
                "local_name": cfg.local_name,
                "tx_power_dbm": None,
                "appearance_code": None,
                "appearance_hex": None,
                "le_role": None,
                "flags": self._make_flags(discoverable),
                "service_uuids": [normalize_uuid(u) for u in cfg.service_uuids],
                "service_data": self._service_data(cfg.service_data_uuid, cfg.service_data_prefix, seq),
                "manufacturer_data": self._manufacturer_data(cfg.manufacturer_company_id, cfg.manufacturer_data_prefix, seq),
                "ad_structures": [],
                "parse_errors": [],
                # Synthetic truth labels / metadata
                "device_truth_id": cfg.device_truth_id,
                "scenario_name": cfg.scenario_name,
                "expected_high_exposure": cfg.expected_high_exposure,
                "truth_device_type": cfg.truth_device_type,
            }
            records.append(record)
            seq += 1

        return records

    def scenario_stable_single_device(self, start: datetime) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        cfg = DeviceConfig(
            device_truth_id="stable_sensor_1",
            scenario_name="stable_single_device",
            addr_type="public",
            adv_type="ADV_IND",
            local_name="Jacob-Keyboard",
            service_uuids=["1812"],
            manufacturer_company_id=76,
            manufacturer_data_prefix="a1b2",
            service_data_uuid=None,
            service_data_prefix=None,
            rssi_mean=-48,
            rssi_std=3,
            interval_seconds=10,
            packet_loss=0.05,
            address_rotation_seconds=None,
            expected_high_exposure=True,
            truth_device_type="human_interface",
        )
        return self._emit_device(cfg, start, 300), [asdict(cfg)]

    def scenario_rotating_address_stable_tokens(self, start: datetime) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        cfg = DeviceConfig(
            device_truth_id="rotating_beacon_1",
            scenario_name="rotating_address_stable_tokens",
            addr_type="random",
            adv_type="ADV_IND",
            local_name="TempSensor-A",
            service_uuids=["1809"],
            manufacturer_company_id=4660,
            manufacturer_data_prefix="cafe",
            service_data_uuid="1809",
            service_data_prefix="beef",
            rssi_mean=-62,
            rssi_std=5,
            interval_seconds=12,
            packet_loss=0.08,
            address_rotation_seconds=60,
            expected_high_exposure=True,
            truth_device_type="medical_health",
        )
        return self._emit_device(cfg, start, 360), [asdict(cfg)]

    def scenario_two_similar_devices(self, start: datetime) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        a = DeviceConfig(
            device_truth_id="similar_hid_a",
            scenario_name="two_similar_devices",
            addr_type="random",
            adv_type="ADV_IND",
            local_name="Keyboard-A",
            service_uuids=["1812"],
            manufacturer_company_id=1,
            manufacturer_data_prefix="1111",
            service_data_uuid=None,
            service_data_prefix=None,
            rssi_mean=-45,
            rssi_std=4,
            interval_seconds=11,
            packet_loss=0.04,
            address_rotation_seconds=None,
            expected_high_exposure=True,
            truth_device_type="human_interface",
        )
        b = DeviceConfig(
            device_truth_id="similar_hid_b",
            scenario_name="two_similar_devices",
            addr_type="random",
            adv_type="ADV_IND",
            local_name="Keyboard-B",
            service_uuids=["1812"],
            manufacturer_company_id=1,
            manufacturer_data_prefix="2222",
            service_data_uuid=None,
            service_data_prefix=None,
            rssi_mean=-70,
            rssi_std=5,
            interval_seconds=13,
            packet_loss=0.06,
            address_rotation_seconds=None,
            expected_high_exposure=True,
            truth_device_type="human_interface",
        )
        records = self._emit_device(a, start, 300) + self._emit_device(b, start + timedelta(seconds=20), 280)
        return records, [asdict(a), asdict(b)]

    def scenario_noisy_mixed_environment(self, start: datetime) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        devices = [
            DeviceConfig(
                device_truth_id="noisy_earbuds_1",
                scenario_name="noisy_mixed_environment",
                addr_type="random",
                adv_type="ADV_IND",
                local_name="Earbuds-X",
                service_uuids=["184f"],
                manufacturer_company_id=224,
                manufacturer_data_prefix="aa01",
                service_data_uuid=None,
                service_data_prefix=None,
                rssi_mean=-58,
                rssi_std=8,
                interval_seconds=9,
                packet_loss=0.15,
                address_rotation_seconds=90,
                expected_high_exposure=False,
                truth_device_type="audio_wearable",
            ),
            DeviceConfig(
                device_truth_id="noisy_medical_1",
                scenario_name="noisy_mixed_environment",
                addr_type="public",
                adv_type="ADV_IND",
                local_name=None,
                service_uuids=["180d", "180f"],
                manufacturer_company_id=30583,
                manufacturer_data_prefix="bb02",
                service_data_uuid="180d",
                service_data_prefix="cd",
                rssi_mean=-67,
                rssi_std=9,
                interval_seconds=14,
                packet_loss=0.20,
                address_rotation_seconds=None,
                expected_high_exposure=True,
                truth_device_type="medical_health",
            ),
            DeviceConfig(
                device_truth_id="noisy_beacon_1",
                scenario_name="noisy_mixed_environment",
                addr_type="random",
                adv_type="ADV_NONCONN_IND",
                local_name=None,
                service_uuids=[],
                manufacturer_company_id=301,
                manufacturer_data_prefix="cc03",
                service_data_uuid=None,
                service_data_prefix=None,
                rssi_mean=-80,
                rssi_std=7,
                interval_seconds=7,
                packet_loss=0.25,
                address_rotation_seconds=120,
                expected_high_exposure=False,
                truth_device_type="beacon",
            ),
        ]
        records: List[Dict[str, Any]] = []
        manifest: List[Dict[str, Any]] = []
        offsets = [0, 15, 35]
        durations = [360, 300, 330]
        for cfg, offset, duration in zip(devices, offsets, durations):
            records.extend(self._emit_device(cfg, start + timedelta(seconds=offset), duration))
            manifest.append(asdict(cfg))
        return records, manifest

    def scenario_exposure_mix(self, start: datetime) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        devices = [
            DeviceConfig(
                device_truth_id="high_kb_1",
                scenario_name="exposure_mix",
                addr_type="public",
                adv_type="ADV_IND",
                local_name="OfficeKeyboard",
                service_uuids=["1812"],
                manufacturer_company_id=25,
                manufacturer_data_prefix="d101",
                service_data_uuid=None,
                service_data_prefix=None,
                rssi_mean=-50,
                rssi_std=4,
                interval_seconds=10,
                packet_loss=0.04,
                address_rotation_seconds=None,
                expected_high_exposure=True,
                truth_device_type="human_interface",
            ),
            DeviceConfig(
                device_truth_id="high_medical_2",
                scenario_name="exposure_mix",
                addr_type="public",
                adv_type="ADV_IND",
                local_name="Thermometer-2",
                service_uuids=["1809"],
                manufacturer_company_id=4660,
                manufacturer_data_prefix="d202",
                service_data_uuid="1809",
                service_data_prefix="aa",
                rssi_mean=-57,
                rssi_std=4,
                interval_seconds=12,
                packet_loss=0.05,
                address_rotation_seconds=None,
                expected_high_exposure=True,
                truth_device_type="medical_health",
            ),
            DeviceConfig(
                device_truth_id="low_beacon_2",
                scenario_name="exposure_mix",
                addr_type="random",
                adv_type="ADV_NONCONN_IND",
                local_name=None,
                service_uuids=[],
                manufacturer_company_id=76,
                manufacturer_data_prefix="d303",
                service_data_uuid=None,
                service_data_prefix=None,
                rssi_mean=-79,
                rssi_std=5,
                interval_seconds=8,
                packet_loss=0.10,
                address_rotation_seconds=120,
                expected_high_exposure=False,
                truth_device_type="beacon",
            ),
            DeviceConfig(
                device_truth_id="low_audio_2",
                scenario_name="exposure_mix",
                addr_type="random",
                adv_type="ADV_SCAN_IND",
                local_name=None,
                service_uuids=["184f"],
                manufacturer_company_id=224,
                manufacturer_data_prefix="d404",
                service_data_uuid=None,
                service_data_prefix=None,
                rssi_mean=-72,
                rssi_std=6,
                interval_seconds=9,
                packet_loss=0.12,
                address_rotation_seconds=90,
                expected_high_exposure=False,
                truth_device_type="audio_wearable",
            ),
        ]
        records: List[Dict[str, Any]] = []
        manifest: List[Dict[str, Any]] = []
        for idx, cfg in enumerate(devices):
            records.extend(self._emit_device(cfg, start + timedelta(seconds=idx * 20), 300))
            manifest.append(asdict(cfg))
        return records, manifest

    def generate_all(self, start: datetime) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        scenarios = [
            self.scenario_stable_single_device,
            self.scenario_rotating_address_stable_tokens,
            self.scenario_two_similar_devices,
            self.scenario_noisy_mixed_environment,
            self.scenario_exposure_mix,
        ]

        all_records: List[Dict[str, Any]] = []
        all_manifest: List[Dict[str, Any]] = []
        cursor = start

        for scenario_fn in scenarios:
            records, manifest = scenario_fn(cursor)
            all_records.extend(records)
            all_manifest.extend(manifest)
            cursor += timedelta(minutes=12)

        all_records.sort(key=lambda r: r["ts"])
        return all_records, all_manifest


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate synthetic BLE advertisement traces for evaluation.")
    parser.add_argument("output", help="Output JSONL path")
    parser.add_argument("--manifest", help="Optional manifest JSON path")
    parser.add_argument("--seed", type=int, default=7, help="Random seed (default: 7)")
    parser.add_argument(
        "--start-time",
        default="2026-01-01T12:00:00+00:00",
        help="ISO-8601 UTC start time (default: 2026-01-01T12:00:00+00:00)",
    )
    return parser


def main() -> None:
    args = build_arg_parser().parse_args()
    start = datetime.fromisoformat(args.start_time)
    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)

    gen = SyntheticTraceGenerator(seed=args.seed)
    records, manifest = gen.generate_all(start)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    write_jsonl(output_path, records)
    print(f"Wrote {len(records)} synthetic observations to {output_path}")

    if args.manifest:
        manifest_path = Path(args.manifest)
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        with manifest_path.open("w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
        print(f"Wrote manifest to {manifest_path}")


if __name__ == "__main__":
    main()
