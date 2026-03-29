"""Shared fixtures for the avclass_label test suite."""

import json

import pytest


@pytest.fixture()
def sample_vt_report() -> dict:
    """Return a realistic but minimal VirusTotal JSON report as a dict."""
    return {
        "data": {
            "id": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            "type": "file",
            "attributes": {
                "md5": "44d88612fea8a8f36de82e1278abb02f",
                "sha1": "3395856ce81f2b7382dee72602f798b642f14140",
                "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                "meaningful_name": "eicar_test_file",
                "last_analysis_results": {
                    "Kaspersky": {
                        "category": "malicious",
                        "engine_name": "Kaspersky",
                        "engine_version": "21.0.1.45",
                        "result": "EICAR-Test-File",
                        "method": "exact",
                        "engine_update": "20230101",
                    },
                    "McAfee": {
                        "category": "malicious",
                        "engine_name": "McAfee",
                        "engine_version": "6.0.6.653",
                        "result": "EICAR test file",
                        "method": "exact",
                        "engine_update": "20230101",
                    },
                },
                "last_analysis_stats": {
                    "malicious": 2,
                    "suspicious": 0,
                    "undetected": 0,
                    "harmless": 0,
                    "timeout": 0,
                    "confirmed-timeout": 0,
                    "failure": 0,
                    "type-unsupported": 0,
                },
            },
        }
    }


@pytest.fixture()
def populated_tmp_dir(tmp_path, sample_vt_report) -> dict:
    """Create a temp directory tree with valid/invalid JSON and non-JSON files.

    Returns a dict with keys: root, valid_files, invalid_file, non_json.
    """
    valid_files = []

    report_a = tmp_path / "report_aaa.json"
    report_a.write_text(json.dumps(sample_vt_report, indent=2), encoding="utf-8")
    valid_files.append(report_a)

    vt_b = json.loads(json.dumps(sample_vt_report))
    vt_b["data"]["id"] = "b" * 64
    report_b = tmp_path / "report_bbb.json"
    report_b.write_text(json.dumps(vt_b, indent=2), encoding="utf-8")
    valid_files.append(report_b)

    subdir = tmp_path / "subdir"
    subdir.mkdir()
    vt_c = json.loads(json.dumps(sample_vt_report))
    vt_c["data"]["id"] = "c" * 64
    report_c = subdir / "report_ccc.json"
    report_c.write_text(json.dumps(vt_c, indent=2), encoding="utf-8")
    valid_files.append(report_c)

    invalid_file = tmp_path / "bad_report.json"
    invalid_file.write_text("{this is not valid json!!!", encoding="utf-8")

    non_json = []
    readme = tmp_path / "readme.txt"
    readme.write_text("just a text file", encoding="utf-8")
    non_json.append(readme)

    notes = subdir / "notes.md"
    notes.write_text("# notes", encoding="utf-8")
    non_json.append(notes)

    return {
        "root": tmp_path,
        "valid_files": sorted(valid_files),
        "invalid_file": invalid_file,
        "non_json": sorted(non_json),
    }
