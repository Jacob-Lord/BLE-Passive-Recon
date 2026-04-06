from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# ============================================================
# BLE Advertising Data (AD) Type Constants
# ============================================================

AD_TYPE_NAMES: Dict[int, str] = {
    0x01: "Flags",
    0x02: "Incomplete List of 16-bit Service UUIDs",
    0x03: "Complete List of 16-bit Service UUIDs",
    0x04: "Incomplete List of 32-bit Service UUIDs",
    0x05: "Complete List of 32-bit Service UUIDs",
    0x06: "Incomplete List of 128-bit Service UUIDs",
    0x07: "Complete List of 128-bit Service UUIDs",
    0x08: "Shortened Local Name",
    0x09: "Complete Local Name",
    0x0A: "Tx Power Level",
    0x12: "Slave Connection Interval Range",
    0x14: "List of 16-bit Service Solicitation UUIDs",
    0x15: "List of 128-bit Service Solicitation UUIDs",
    0x16: "Service Data - 16-bit UUID",
    0x19: "Appearance",
    0x1B: "LE Bluetooth Device Address",
    0x1C: "LE Role",
    0x1F: "List of 32-bit Service Solicitation UUIDs",
    0x20: "Service Data - 32-bit UUID",
    0x21: "Service Data - 128-bit UUID",
    0x24: "URI",
    0xFF: "Manufacturer Specific Data",
}


# ============================================================
# Helper Mappings
# ============================================================

# These mappings are used to decode specific fields like Flags and LE Role into human-readable forms.

FLAGS_MAP = {
    0: "LE Limited Discoverable Mode",
    1: "LE General Discoverable Mode",
    2: "BR/EDR Not Supported",
    3: "Simultaneous LE and BR/EDR (Controller)",
    4: "Simultaneous LE and BR/EDR (Host)",
}

LE_ROLE_MAP = {
    0x00: "Only Peripheral Role Supported",
    0x01: "Only Central Role Supported",
    0x02: "Peripheral Role Preferred",
    0x03: "Central Role Preferred",
}


# ============================================================
# Dataclasses
# ============================================================

# Advertisement Data (AD) structure representation
@dataclass
class ADStructure:
    ad_type: int # AD Type value (e.g., 0x01 for Flags)
    ad_type_name: str # Name of the AD Type (e.g., "Flags")
    length: int # Length of the data field
    data_hex: str # Raw data in hexadecimal string form
    decoded: Dict[str, Any] # Decoded fields specific to this AD type (e.g., for Flags, the individual flag bits and their meanings)


# Normalized advertisement record schema
@dataclass
class NormalizedAdvertisementRecord:
    ts: str # Timestamp
    rssi: Optional[int] # Received Signal Strength Indicator
    addr: Optional[str] # MAC Address
    addr_type: Optional[str] # Address Type
    adv_type: Optional[str] # Advertisement Type

    # Raw payload, if available
    payload_hex: Optional[str]

    # Common normalized fields
    local_name: Optional[str]
    tx_power_dbm: Optional[int] # Transmit Power in dBm
    appearance_code: Optional[int] # Bit-wise appearance code as defined by Bluetooth SIG (https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Assigned_Numbers/out/en/Assigned_Numbers.pdf)
    appearance_hex: Optional[str] # Hex string representation of the appearance code (e.g., 0x001 - Phone, 0x002 - Computer, etc.)
    le_role: Optional[str] # LE Role (e.g., "Only Peripheral Role Supported", "Only Central Role Supported", etc.)

    flags: Optional[Dict[str, Any]] # Decoded flags field with raw value, hex representation, and list of flag names
    service_uuids: List[str] # List of service UUIDs advertised by the device
    service_data: List[Dict[str, Any]] # List of service data entries, each with 'uuid' and 'service_data_hex'
    manufacturer_data: List[Dict[str, Any]] # List of manufacturer data entries, each with 'company_id', 'company_id_hex', and 'manufacturer_data_hex'

    ad_structures: List[Dict[str, Any]] # List of all parsed AD structures with their types, raw data, and decoded fields
    parse_errors: List[str] # List of any errors encountered during parsing (e.g., malformed structures)


# ============================================================
# Utility Functions
# ============================================================

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hex(data: bytes) -> str:
    return data.hex()


def _decode_name(data: bytes) -> str:
    return data.decode("utf-8", errors="replace").strip("\x00")


def _int8(value: int) -> int:
    return value - 256 if value > 127 else value


def _format_uuid16(value: int) -> str:
    return f"0000{value:04x}-0000-1000-8000-00805f9b34fb"


def _format_uuid32(value: int) -> str:
    return f"{value:08x}-0000-1000-8000-00805f9b34fb"


def _format_uuid128_le(raw: bytes) -> str:
    """
    BLE AD payloads encode 128-bit UUIDs little-endian.
    Convert to canonical UUID string.
    """
    if len(raw) != 16:
        raise ValueError("128-bit UUID must be exactly 16 bytes")
    b = raw[::-1].hex()
    return f"{b[0:8]}-{b[8:12]}-{b[12:16]}-{b[16:20]}-{b[20:32]}"


def _parse_uuid_list(data: bytes, width: int) -> List[str]:
    uuids: List[str] = []

    if width == 2:
        if len(data) % 2 != 0:
            return uuids
        for i in range(0, len(data), 2):
            value = int.from_bytes(data[i:i + 2], byteorder="little")
            uuids.append(_format_uuid16(value))

    elif width == 4:
        if len(data) % 4 != 0:
            return uuids
        for i in range(0, len(data), 4):
            value = int.from_bytes(data[i:i + 4], byteorder="little")
            uuids.append(_format_uuid32(value))

    elif width == 16:
        if len(data) % 16 != 0:
            return uuids
        for i in range(0, len(data), 16):
            uuids.append(_format_uuid128_le(data[i:i + 16]))

    return uuids


def _parse_flags(data: bytes) -> Dict[str, Any]:
    if not data:
        return {"raw": None, "names": []}

    raw = data[0]
    names = [name for bit, name in FLAGS_MAP.items() if raw & (1 << bit)]

    return {
        "raw": raw,
        "hex": f"0x{raw:02x}",
        "names": names,
        "limited_discoverable": bool(raw & (1 << 0)),
        "general_discoverable": bool(raw & (1 << 1)),
        "br_edr_not_supported": bool(raw & (1 << 2)),
        "simultaneous_le_br_edr_controller": bool(raw & (1 << 3)),
        "simultaneous_le_br_edr_host": bool(raw & (1 << 4)),
    }


# ============================================================
# Core Parser
# ============================================================

class BLEAdvertisementParser:
    """
    Parser for BLE advertising payload bytes (AD structures).
    Also provides a fallback normalizer for Bleak-style decoded data.
    """

    @staticmethod
    def parse_payload(payload: bytes) -> Dict[str, Any]:
        """
        Parse a raw BLE advertising payload into AD structures and a normalized record body.
        Payload format:
            [len][type][data...][len][type][data...]...
        where len includes 1 byte for type + N bytes of data.
        """
        idx = 0
        structures: List[ADStructure] = []
        parse_errors: List[str] = []

        normalized = {
            "local_name": None,
            "tx_power_dbm": None,
            "appearance_code": None,
            "appearance_hex": None,
            "le_role": None,
            "flags": None,
            "service_uuids": [],
            "service_data": [],
            "manufacturer_data": [],
        }

        while idx < len(payload):
            length = payload[idx]

            # Zero-length field means end of significant data
            if length == 0:
                break

            if idx + 1 + length > len(payload):
                parse_errors.append(
                    f"Malformed AD structure at offset {idx}: length={length} exceeds remaining payload"
                )
                break

            ad_type = payload[idx + 1]
            data = payload[idx + 2: idx + 1 + length]

            decoded = BLEAdvertisementParser.decode_ad_structure(ad_type, data)

            structures.append(
                ADStructure(
                    ad_type=ad_type,
                    ad_type_name=AD_TYPE_NAMES.get(ad_type, f"Unknown (0x{ad_type:02x})"),
                    length=length,
                    data_hex=_hex(data),
                    decoded=decoded,
                )
            )

            # Fold parsed info into normalized structure
            BLEAdvertisementParser._merge_decoded_into_normalized(normalized, ad_type, decoded)

            idx += 1 + length

        return {
            "payload_hex": _hex(payload),
            "ad_structures": [asdict(s) for s in structures],
            "parse_errors": parse_errors,
            **normalized,
        }

    @staticmethod
    def decode_ad_structure(ad_type: int, data: bytes) -> Dict[str, Any]:
        if ad_type == 0x01:  # Flags
            return _parse_flags(data)

        if ad_type in (0x02, 0x03):  # 16-bit UUIDs
            return {"uuids": _parse_uuid_list(data, 2)}

        if ad_type in (0x04, 0x05):  # 32-bit UUIDs
            return {"uuids": _parse_uuid_list(data, 4)}

        if ad_type in (0x06, 0x07):  # 128-bit UUIDs
            return {"uuids": _parse_uuid_list(data, 16)}

        if ad_type in (0x08, 0x09):  # Local name
            return {"name": _decode_name(data)}

        if ad_type == 0x0A:  # Tx Power
            if len(data) >= 1:
                return {"tx_power_dbm": _int8(data[0])}
            return {}

        if ad_type == 0x16:  # Service Data - 16-bit UUID
            if len(data) >= 2:
                uuid16 = int.from_bytes(data[0:2], byteorder="little")
                return {
                    "uuid": _format_uuid16(uuid16),
                    "service_data_hex": _hex(data[2:]),
                }
            return {}

        if ad_type == 0x20:  # Service Data - 32-bit UUID
            if len(data) >= 4:
                uuid32 = int.from_bytes(data[0:4], byteorder="little")
                return {
                    "uuid": _format_uuid32(uuid32),
                    "service_data_hex": _hex(data[4:]),
                }
            return {}

        if ad_type == 0x21:  # Service Data - 128-bit UUID
            if len(data) >= 16:
                return {
                    "uuid": _format_uuid128_le(data[0:16]),
                    "service_data_hex": _hex(data[16:]),
                }
            return {}

        if ad_type == 0x19:  # Appearance
            if len(data) >= 2:
                code = int.from_bytes(data[0:2], byteorder="little")
                return {
                    "appearance_code": code,
                    "appearance_hex": f"0x{code:04x}",
                }
            return {}

        if ad_type == 0x1C:  # LE Role
            if len(data) >= 1:
                return {
                    "le_role_code": data[0],
                    "le_role": LE_ROLE_MAP.get(data[0], f"Unknown ({data[0]})"),
                }
            return {}

        if ad_type == 0xFF:  # Manufacturer Specific Data
            if len(data) >= 2:
                company_id = int.from_bytes(data[0:2], byteorder="little")
                return {
                    "company_id": company_id,
                    "company_id_hex": f"0x{company_id:04x}",
                    "manufacturer_data_hex": _hex(data[2:]),
                }
            return {"manufacturer_data_hex": ""}

        # Unknown / unhandled
        return {}

    @staticmethod
    def _merge_decoded_into_normalized(
        normalized: Dict[str, Any],
        ad_type: int,
        decoded: Dict[str, Any],
    ) -> None:
        if ad_type == 0x01:
            normalized["flags"] = decoded

        elif ad_type in (0x02, 0x03, 0x04, 0x05, 0x06, 0x07):
            for uuid in decoded.get("uuids", []):
                if uuid not in normalized["service_uuids"]:
                    normalized["service_uuids"].append(uuid)

        elif ad_type in (0x08, 0x09):
            if normalized["local_name"] is None:
                normalized["local_name"] = decoded.get("name")

        elif ad_type == 0x0A:
            normalized["tx_power_dbm"] = decoded.get("tx_power_dbm")

        elif ad_type == 0x19:
            normalized["appearance_code"] = decoded.get("appearance_code")
            normalized["appearance_hex"] = decoded.get("appearance_hex")

        elif ad_type == 0x1C:
            normalized["le_role"] = decoded.get("le_role")

        elif ad_type in (0x16, 0x20, 0x21):
            normalized["service_data"].append(decoded)

        elif ad_type == 0xFF:
            normalized["manufacturer_data"].append(decoded)

    @staticmethod
    def normalize_from_raw_payload(
        payload: bytes,
        *,
        ts: Optional[str] = None,
        rssi: Optional[int] = None,
        addr: Optional[str] = None,
        addr_type: Optional[str] = None,
        adv_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        parsed = BLEAdvertisementParser.parse_payload(payload)

        record = NormalizedAdvertisementRecord(
            ts=ts or _now_iso(),
            rssi=rssi,
            addr=addr,
            addr_type=addr_type,
            adv_type=adv_type,
            payload_hex=parsed["payload_hex"],
            local_name=parsed["local_name"],
            tx_power_dbm=parsed["tx_power_dbm"],
            appearance_code=parsed["appearance_code"],
            appearance_hex=parsed["appearance_hex"],
            le_role=parsed["le_role"],
            flags=parsed["flags"],
            service_uuids=parsed["service_uuids"],
            service_data=parsed["service_data"],
            manufacturer_data=parsed["manufacturer_data"],
            ad_structures=parsed["ad_structures"],
            parse_errors=parsed["parse_errors"],
        )

        return asdict(record)

    @staticmethod
    def normalize_from_bleak(
        advertisement_data: Any,
        *,
        ts: Optional[str] = None,
        rssi: Optional[int] = None,
        addr: Optional[str] = None,
        addr_type: Optional[str] = None,
        adv_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Best-effort fallback for Bleak AdvertisementData objects or equivalent dicts.

        On Windows, Bleak often exposes decoded fields but not the raw advertising payload.
        This method normalizes those exposed fields into the same schema shape.
        """
        def _get(obj: Any, name: str, default: Any = None) -> Any:
            if isinstance(obj, dict):
                return obj.get(name, default)
            return getattr(obj, name, default)

        local_name = _get(advertisement_data, "local_name")
        service_uuids = list(_get(advertisement_data, "service_uuids", []) or [])
        tx_power = _get(advertisement_data, "tx_power")

        manufacturer_data_raw = _get(advertisement_data, "manufacturer_data", {}) or {}
        service_data_raw = _get(advertisement_data, "service_data", {}) or {}

        manufacturer_data: List[Dict[str, Any]] = []
        for company_id, data in manufacturer_data_raw.items():
            if isinstance(data, bytes):
                data_hex = _hex(data)
            elif isinstance(data, bytearray):
                data_hex = _hex(bytes(data))
            else:
                data_hex = str(data)

            manufacturer_data.append({
                "company_id": int(company_id),
                "company_id_hex": f"0x{int(company_id):04x}",
                "manufacturer_data_hex": data_hex,
            })

        service_data: List[Dict[str, Any]] = []
        for uuid, data in service_data_raw.items():
            if isinstance(data, bytes):
                data_hex = _hex(data)
            elif isinstance(data, bytearray):
                data_hex = _hex(bytes(data))
            else:
                data_hex = str(data)

            service_data.append({
                "uuid": str(uuid).lower(),
                "service_data_hex": data_hex,
            })

        record = NormalizedAdvertisementRecord(
            ts=ts or _now_iso(),
            rssi=rssi if rssi is not None else _get(advertisement_data, "rssi"),
            addr=addr,
            addr_type=addr_type,
            adv_type=adv_type,
            payload_hex=None,  # Usually unavailable from Bleak on Windows
            local_name=local_name,
            tx_power_dbm=tx_power,
            appearance_code=None,
            appearance_hex=None,
            le_role=None,
            flags=None,
            service_uuids=[str(u).lower() for u in service_uuids],
            service_data=service_data,
            manufacturer_data=manufacturer_data,
            ad_structures=[],
            parse_errors=[],
        )

        return asdict(record)


# ============================================================
# Example Usage
# ============================================================

if __name__ == "__main__":  
    # Example raw payload:
    # 02 01 06       -> Flags
    # 03 03 0D 18    -> Complete List of 16-bit UUIDs: 0x180D (Heart Rate)
    # 0B 09 54 65 73 74 20 44 65 76 69 63 65 -> Complete Name: "Test Device"
    sample_payload = bytes.fromhex(
        "02010603030D180B095465737420446576696365"
    )

    parsed = BLEAdvertisementParser.normalize_from_raw_payload(
        sample_payload,
        rssi=-61,
        addr="AA:BB:CC:DD:EE:FF",
        addr_type="random",
        adv_type="ADV_IND",
    )

    import json
    print(json.dumps(parsed, indent=2))