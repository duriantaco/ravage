# ruff: noqa: PLR2004
from __future__ import annotations

import pytest
from ravage.satcom.contracts import SatcomFormatError
from ravage.satcom.tle import TLE_LINE_LENGTH, parse_tle_catalog


def _checksum_line(body: str) -> str:
    assert len(body) == TLE_LINE_LENGTH - 1
    checksum = sum(int(char) if char.isdecimal() else 1 if char == "-" else 0 for char in body)
    return f"{body}{checksum % 10}"


def _tle_pair(*, catalog_id: str = "25544") -> tuple[str, str]:
    line1 = [" "] * 68
    line1[0:2] = "1 "
    line1[2:7] = catalog_id
    line1[7] = "U"
    line1[9:17] = "98067A  "
    line1[18:20] = "24"
    line1[20:32] = "001.50000000"

    line2 = [" "] * 68
    line2[0:2] = "2 "
    line2[2:7] = catalog_id
    line2[8:16] = " 51.6416"
    line2[17:25] = " 50.0000"
    line2[26:33] = "0005000"
    line2[34:42] = "100.0000"
    line2[43:51] = "260.0000"
    line2[52:63] = "15.50000000"
    line2[63:68] = "43000"
    return _checksum_line("".join(line1)), _checksum_line("".join(line2))


def test_parses_named_checksum_valid_tle_without_retaining_raw_lines() -> None:
    line1, line2 = _tle_pair()

    records = parse_tle_catalog(f"ISS (ZARYA)\n{line1}\n{line2}\n")

    assert len(records) == 1
    record = records[0]
    assert record.object_name == "ISS (ZARYA)"
    assert record.catalog_id == "25544"
    assert record.epoch_year == 2024
    assert record.epoch_day == 1.5
    assert record.inclination_degrees == 51.6416
    assert record.eccentricity == 0.0005
    assert record.mean_motion_revolutions_per_day == 15.5
    assert record.line1_sha256.startswith("sha256:")
    assert line1 not in str(record.to_json(evidence_ref="artifact:test"))


def test_accepts_zero_prefixed_name_and_unnamed_pairs() -> None:
    line1, line2 = _tle_pair()
    named = parse_tle_catalog(f"0 ISS\n{line1}\n{line2}\n")
    unnamed = parse_tle_catalog(f"{line1}\n{line2}\n")

    assert named[0].object_name == "ISS"
    assert unnamed[0].object_name == ""


def test_rejects_bad_checksum_mismatched_catalog_and_incomplete_pair() -> None:
    line1, line2 = _tle_pair()
    _wrong_line1, wrong_line2 = _tle_pair(catalog_id="12345")
    bad_checksum = f"{line1[:-1]}{(int(line1[-1]) + 1) % 10}"

    with pytest.raises(SatcomFormatError, match="checksum"):
        parse_tle_catalog(f"{bad_checksum}\n{line2}\n")
    with pytest.raises(SatcomFormatError, match="identifiers disagree"):
        parse_tle_catalog(f"{line1}\n{wrong_line2}\n")
    with pytest.raises(SatcomFormatError, match="complete line pair"):
        parse_tle_catalog(line1)


def test_rejects_non_ascii_and_record_overflow() -> None:
    line1, line2 = _tle_pair()

    with pytest.raises(SatcomFormatError, match="ASCII"):
        parse_tle_catalog(f"{line1[:-2]}☃{line1[-1]}\n{line2}\n")
    with pytest.raises(SatcomFormatError, match="record limit"):
        parse_tle_catalog(f"{line1}\n{line2}\n{line1}\n{line2}\n", max_records=1)


def test_rejects_unsupported_classification_and_alpha5_catalog_symbols() -> None:
    line1, line2 = _tle_pair()
    bad_classification = _checksum_line(f"{line1[:7]}X{line1[8:-1]}")
    invalid_alpha_line1, invalid_alpha_line2 = _tle_pair(catalog_id="I1234")

    with pytest.raises(SatcomFormatError, match="classification"):
        parse_tle_catalog(f"{bad_classification}\n{line2}\n")
    with pytest.raises(SatcomFormatError, match="identifiers disagree"):
        parse_tle_catalog(f"{invalid_alpha_line1}\n{invalid_alpha_line2}\n")


def test_rejects_tle_text_before_unbounded_line_materialization() -> None:
    with pytest.raises(SatcomFormatError, match="text limit"):
        parse_tle_catalog("A" * 400_000)
