import asyncio
import json
from pathlib import Path

from bleak import BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

from advertisement_parser import BLEAdvertisementParser

OUTPUT_PATH = Path("captures/ble_capture.jsonl")


def handle_advertisement(device: BLEDevice, adv: AdvertisementData) -> None:
    record = BLEAdvertisementParser.normalize_from_bleak(
        adv,
        addr=device.address,
        rssi=adv.rssi,
        # Bleak on Windows usually gives parsed fields here - addr_type / adv_type may not always be exposed through the high-level API
        addr_type=None,
        adv_type=None,
    )

    with OUTPUT_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")

    print(
        f"[{record['ts']}] "
        f"{record['addr']} "
        f"RSSI={record['rssi']} "
        f"name={record['local_name']} "
        f"uuids={record['service_uuids']}"
    )


async def main() -> None:
    scanner = BleakScanner(
        detection_callback=handle_advertisement,
        scanning_mode="passive",  # This is important as this project is structured around passive scanning (not sending scan requests to devices)
    )

    print("Scanning... Press Ctrl+C to stop.")
    await scanner.start()
    try:
        while True:
            await asyncio.sleep(1)
    finally:
        await scanner.stop()


if __name__ == "__main__":
    asyncio.run(main())