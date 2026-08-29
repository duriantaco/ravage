# ruff: noqa: C901, EM101, EM102, TRY003
"""Strict, offline Two-Line Element catalog parsing and validation."""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass

from ravage.satcom.contracts import (
    MAX_SAFE_TEXT_CHARS,
    MAX_TLE_RECORDS,
    SatcomFormatError,
    safe_text,
)

TLE_LINE_LENGTH = 69
_CATALOG_ID_RE = re.compile(r"^(?:[0-9]{5}|[A-HJ-NP-Z][0-9]{4})$")
_PRINTABLE_LINE_RE = re.compile(r"^[ -~]{69}$")
_CLASSIFICATIONS = frozenset({"C", "S", "U"})
_TLE_YEAR_1900_CUTOFF = 57
_TLE_DAY_UPPER_BOUND = 367
_MAX_TLE_TEXT_CHARS = MAX_TLE_RECORDS * ((TLE_LINE_LENGTH + 1) * 2 + MAX_SAFE_TEXT_CHARS + 1)


@dataclass(frozen=True, slots=True)
class TleRecord:
    record_index: int
    object_name: str
    catalog_id: str
    classification: str
    international_designator: str
    epoch_year: int
    epoch_day: float
    inclination_degrees: float
    right_ascension_degrees: float
    eccentricity: float
    argument_of_perigee_degrees: float
    mean_anomaly_degrees: float
    mean_motion_revolutions_per_day: float
    revolution_number: int
    line1_sha256: str
    line2_sha256: str

    def to_json(self, *, evidence_ref: str) -> dict[str, object]:
        return {
            "kind": "tle_record",
            "record_index": self.record_index,
            "object_name": self.object_name,
            "catalog_id": self.catalog_id,
            "classification": self.classification,
            "international_designator": self.international_designator,
            "epoch_year": self.epoch_year,
            "epoch_day": self.epoch_day,
            "inclination_degrees": self.inclination_degrees,
            "right_ascension_degrees": self.right_ascension_degrees,
            "eccentricity": self.eccentricity,
            "argument_of_perigee_degrees": self.argument_of_perigee_degrees,
            "mean_anomaly_degrees": self.mean_anomaly_degrees,
            "mean_motion_revolutions_per_day": self.mean_motion_revolutions_per_day,
            "revolution_number": self.revolution_number,
            "line1_sha256": self.line1_sha256,
            "line2_sha256": self.line2_sha256,
            "evidence_ref": evidence_ref,
        }


def parse_tle_catalog(text: str, *, max_records: int = MAX_TLE_RECORDS) -> tuple[TleRecord, ...]:
    """Parse named or unnamed checksum-valid TLE pairs without orbital propagation."""
    if not isinstance(text, str):
        raise SatcomFormatError("TLE artifact must be text")
    if "\x00" in text:
        raise SatcomFormatError("TLE artifact contains a NUL byte")
    if not text.isascii():
        raise SatcomFormatError("TLE artifact must contain ASCII text")
    if len(text) > _MAX_TLE_TEXT_CHARS:
        raise SatcomFormatError("TLE artifact exceeds the text limit")
    if not 0 < max_records <= MAX_TLE_RECORDS:
        raise SatcomFormatError("TLE record limit is invalid")

    lines = [line.removesuffix("\r") for line in text.splitlines() if line.strip()]
    if not lines:
        raise SatcomFormatError("TLE catalog is empty")

    records: list[TleRecord] = []
    cursor = 0
    while cursor < len(lines):
        if len(records) >= max_records:
            raise SatcomFormatError("TLE catalog exceeds the record limit")
        object_name = ""
        if not lines[cursor].startswith("1 "):
            if lines[cursor].startswith("2 "):
                raise SatcomFormatError(f"TLE line 2 has no preceding line 1 at item {cursor}")
            raw_name = lines[cursor].removeprefix("0 ")
            object_name = safe_text(raw_name, label="TLE object name")
            cursor += 1
        if cursor + 1 >= len(lines):
            raise SatcomFormatError("TLE catalog ends before a complete line pair")
        line1 = lines[cursor]
        line2 = lines[cursor + 1]
        cursor += 2
        records.append(
            _parse_pair(
                line1,
                line2,
                object_name=object_name,
                record_index=len(records),
            )
        )
    return tuple(records)


def _parse_pair(
    line1: str,
    line2: str,
    *,
    object_name: str,
    record_index: int,
) -> TleRecord:
    _validate_line(line1, expected_number="1", record_index=record_index)
    _validate_line(line2, expected_number="2", record_index=record_index)
    catalog1 = line1[2:7]
    catalog2 = line2[2:7]
    if not _CATALOG_ID_RE.fullmatch(catalog1) or catalog1 != catalog2:
        raise SatcomFormatError(f"TLE catalog identifiers disagree at record {record_index}")

    classification = line1[7]
    if classification not in _CLASSIFICATIONS:
        raise SatcomFormatError(f"invalid TLE classification at record {record_index}")
    international_designator = line1[9:17].strip()
    if international_designator and not all(
        character.isascii() and (character.isalnum() or character == "-")
        for character in international_designator
    ):
        raise SatcomFormatError(f"invalid TLE international designator at record {record_index}")

    epoch_short_year = _integer(line1[18:20], label="epoch year", record_index=record_index)
    epoch_year = (
        1900 + epoch_short_year
        if epoch_short_year >= _TLE_YEAR_1900_CUTOFF
        else 2000 + epoch_short_year
    )
    epoch_day = _number(line1[20:32], label="epoch day", record_index=record_index)
    if not 0 < epoch_day < _TLE_DAY_UPPER_BOUND:
        raise SatcomFormatError(f"TLE epoch day is outside range at record {record_index}")

    inclination = _angle(
        line2[8:16],
        label="inclination",
        record_index=record_index,
        inclusive_upper=True,
        upper=180.0,
    )
    right_ascension = _angle(line2[17:25], label="right ascension", record_index=record_index)
    eccentricity_digits = line2[26:33]
    if not eccentricity_digits.isdecimal():
        raise SatcomFormatError(f"invalid TLE eccentricity at record {record_index}")
    eccentricity = float(f"0.{eccentricity_digits}")
    argument_of_perigee = _angle(
        line2[34:42], label="argument of perigee", record_index=record_index
    )
    mean_anomaly = _angle(line2[43:51], label="mean anomaly", record_index=record_index)
    mean_motion = _number(line2[52:63], label="mean motion", record_index=record_index)
    if mean_motion <= 0:
        raise SatcomFormatError(f"TLE mean motion is not positive at record {record_index}")
    revolution_number = _integer(line2[63:68], label="revolution number", record_index=record_index)

    return TleRecord(
        record_index=record_index,
        object_name=object_name,
        catalog_id=catalog1,
        classification=classification,
        international_designator=international_designator,
        epoch_year=epoch_year,
        epoch_day=epoch_day,
        inclination_degrees=inclination,
        right_ascension_degrees=right_ascension,
        eccentricity=eccentricity,
        argument_of_perigee_degrees=argument_of_perigee,
        mean_anomaly_degrees=mean_anomaly,
        mean_motion_revolutions_per_day=mean_motion,
        revolution_number=revolution_number,
        line1_sha256=f"sha256:{hashlib.sha256(line1.encode('ascii')).hexdigest()}",
        line2_sha256=f"sha256:{hashlib.sha256(line2.encode('ascii')).hexdigest()}",
    )


def _validate_line(line: str, *, expected_number: str, record_index: int) -> None:
    if not _PRINTABLE_LINE_RE.fullmatch(line):
        raise SatcomFormatError(
            f"TLE line {expected_number} must be exactly {TLE_LINE_LENGTH} ASCII characters "
            f"at record {record_index}"
        )
    if line[0] != expected_number or line[1] != " ":
        raise SatcomFormatError(
            f"invalid TLE line {expected_number} marker at record {record_index}"
        )
    if not line[-1].isdecimal() or _tle_checksum(line) != int(line[-1]):
        raise SatcomFormatError(
            f"invalid TLE line {expected_number} checksum at record {record_index}"
        )


def _tle_checksum(line: str) -> int:
    total = 0
    for character in line[:-1]:
        if character.isdecimal():
            total += int(character)
        elif character == "-":
            total += 1
    return total % 10


def _number(value: str, *, label: str, record_index: int) -> float:
    try:
        result = float(value)
    except ValueError as exc:
        raise SatcomFormatError(f"invalid TLE {label} at record {record_index}") from exc
    if not math.isfinite(result):
        raise SatcomFormatError(f"invalid TLE {label} at record {record_index}")
    return result


def _integer(value: str, *, label: str, record_index: int) -> int:
    text = value.strip()
    if not text.isdecimal():
        raise SatcomFormatError(f"invalid TLE {label} at record {record_index}")
    return int(text)


def _angle(
    value: str,
    *,
    label: str,
    record_index: int,
    upper: float = 360.0,
    inclusive_upper: bool = False,
) -> float:
    angle = _number(value, label=label, record_index=record_index)
    within_upper = angle <= upper if inclusive_upper else angle < upper
    if angle < 0 or not within_upper:
        raise SatcomFormatError(f"TLE {label} is outside range at record {record_index}")
    return angle


__all__ = ["TLE_LINE_LENGTH", "TleRecord", "parse_tle_catalog"]
