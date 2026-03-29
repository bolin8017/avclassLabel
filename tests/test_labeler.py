"""Tests for the Labeler class."""

import csv
import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from avclass_label.config import Config
from avclass_label.labeler import Labeler


def _make_labeler(input_dir: Path) -> Labeler:
    """Shortcut: build a Labeler from a directory path."""
    return Labeler(Config(input_dir))


# ===================================================================
# _collect_files
# ===================================================================


class TestCollectFiles:
    """Verify recursive .json discovery."""

    def test_finds_all_json_files(self, populated_tmp_dir):
        labeler = _make_labeler(populated_tmp_dir["root"])
        labeler._collect_files()

        all_json = sorted(populated_tmp_dir["valid_files"] + [populated_tmp_dir["invalid_file"]])
        assert labeler._file_list == all_json

    def test_ignores_non_json_files(self, populated_tmp_dir):
        labeler = _make_labeler(populated_tmp_dir["root"])
        labeler._collect_files()

        for non_json_path in populated_tmp_dir["non_json"]:
            assert non_json_path not in labeler._file_list

    def test_empty_directory(self, tmp_path):
        labeler = _make_labeler(tmp_path)
        labeler._collect_files()
        assert labeler._file_list == []

    def test_directory_with_only_non_json(self, tmp_path):
        (tmp_path / "data.csv").write_text("a,b", encoding="utf-8")
        (tmp_path / "image.png").write_bytes(b"\x89PNG")
        labeler = _make_labeler(tmp_path)
        labeler._collect_files()
        assert labeler._file_list == []


# ===================================================================
# _convert_to_one_line
# ===================================================================


class TestConvertToOneLine:
    """Verify JSON -> single-line conversion."""

    def test_valid_json_becomes_single_line(self, tmp_path, sample_vt_report):
        json_file = tmp_path / "report.json"
        json_file.write_text(json.dumps(sample_vt_report, indent=4), encoding="utf-8")

        result = Labeler._convert_to_one_line(json_file)

        assert result is not None
        assert "\n" not in result
        assert json.loads(result) == sample_vt_report

    def test_compact_separators(self, tmp_path, sample_vt_report):
        json_file = tmp_path / "report.json"
        json_file.write_text(json.dumps(sample_vt_report, indent=2), encoding="utf-8")

        result = Labeler._convert_to_one_line(json_file)

        assert ", " not in result
        assert ": " not in result

    def test_invalid_json_returns_none(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("{not json!", encoding="utf-8")

        assert Labeler._convert_to_one_line(bad) is None

    def test_missing_file_returns_none(self, tmp_path):
        assert Labeler._convert_to_one_line(tmp_path / "ghost.json") is None

    @pytest.mark.parametrize(
        "content, expected_roundtrip",
        [
            ('{"a": 1}', {"a": 1}),
            ("[]", []),
            ('{"nested": {"x": [1,2,3]}}', {"nested": {"x": [1, 2, 3]}}),
            ('"just a string"', "just a string"),
        ],
        ids=["simple-obj", "empty-list", "nested", "bare-string"],
    )
    def test_various_json_shapes(self, tmp_path, content, expected_roundtrip):
        f = tmp_path / "data.json"
        f.write_text(content, encoding="utf-8")

        result = Labeler._convert_to_one_line(f)
        assert json.loads(result) == expected_roundtrip


# ===================================================================
# _process_json (subprocess mocked)
# ===================================================================


class TestProcessJson:
    """Verify _process_json without a real avclass binary."""

    def test_successful_label(self, tmp_path, sample_vt_report):
        json_file = tmp_path / "malware_sample.json"
        json_file.write_text(json.dumps(sample_vt_report), encoding="utf-8")

        mock_result = MagicMock()
        mock_result.stdout = "malware_sample\teicar\n"

        with patch("avclass_label.labeler.subprocess.run", return_value=mock_result):
            name, label = Labeler._process_json(json_file)

        assert name == "malware_sample"
        assert label == "eicar"

    def test_tmp_file_is_cleaned_up(self, tmp_path, sample_vt_report):
        json_file = tmp_path / "sample.json"
        json_file.write_text(json.dumps(sample_vt_report), encoding="utf-8")

        mock_result = MagicMock()
        mock_result.stdout = "sample\tclean\n"

        with patch("avclass_label.labeler.subprocess.run", return_value=mock_result):
            Labeler._process_json(json_file)

        # No .jsonl temp files should remain
        assert list(tmp_path.glob("*.jsonl")) == []

    def test_subprocess_error_returns_error_label(self, tmp_path, sample_vt_report):
        json_file = tmp_path / "sample.json"
        json_file.write_text(json.dumps(sample_vt_report), encoding="utf-8")

        with patch(
            "avclass_label.labeler.subprocess.run",
            side_effect=subprocess.CalledProcessError(1, "avclass"),
        ):
            name, label = Labeler._process_json(json_file)

        assert name == "sample"
        assert label == "Error"

    def test_os_error_returns_error_label(self, tmp_path, sample_vt_report):
        json_file = tmp_path / "sample.json"
        json_file.write_text(json.dumps(sample_vt_report), encoding="utf-8")

        with patch(
            "avclass_label.labeler.subprocess.run",
            side_effect=OSError("binary not found"),
        ):
            name, label = Labeler._process_json(json_file)

        assert name == "sample"
        assert label == "Error"

    def test_invalid_json_skips_subprocess(self, tmp_path):
        bad = tmp_path / "broken.json"
        bad.write_text("NOT JSON", encoding="utf-8")

        with patch("avclass_label.labeler.subprocess.run") as mock_run:
            name, label = Labeler._process_json(bad)

        assert name == "broken"
        assert label == "Error"
        mock_run.assert_not_called()

    def test_uses_stem_for_filename(self, tmp_path, sample_vt_report):
        json_file = tmp_path / "abc123def.json"
        json_file.write_text(json.dumps(sample_vt_report), encoding="utf-8")

        mock_result = MagicMock()
        mock_result.stdout = "abc123def\tmalware_family\n"

        with patch("avclass_label.labeler.subprocess.run", return_value=mock_result):
            name, _ = Labeler._process_json(json_file)

        assert name == "abc123def"

    def test_uses_list_form_command(self, tmp_path, sample_vt_report):
        """Subprocess is called with a list, not a shell string."""
        json_file = tmp_path / "sample.json"
        json_file.write_text(json.dumps(sample_vt_report), encoding="utf-8")

        mock_result = MagicMock()
        mock_result.stdout = "sample\tlabel\n"

        with patch("avclass_label.labeler.subprocess.run", return_value=mock_result) as mock_run:
            Labeler._process_json(json_file)

        called_cmd = mock_run.call_args[0][0]
        assert isinstance(called_cmd, list)
        assert called_cmd[0] == "avclass"
        assert called_cmd[1] == "-f"

    def test_tab_split_handles_spaces_in_filename(self, tmp_path, sample_vt_report):
        """Using tab split correctly extracts label even with spaces in avclass output."""
        json_file = tmp_path / "file with spaces.json"
        json_file.write_text(json.dumps(sample_vt_report), encoding="utf-8")

        mock_result = MagicMock()
        mock_result.stdout = "file with spaces\teicar\n"

        with patch("avclass_label.labeler.subprocess.run", return_value=mock_result):
            name, label = Labeler._process_json(json_file)

        assert name == "file with spaces"
        assert label == "eicar"


# ===================================================================
# _label_all (end-to-end with mocked subprocess)
# ===================================================================


class TestLabelAll:
    """Integration: _label_all writes a correct CSV."""

    def _mock_subprocess(self, *args, **kwargs):
        """Mock avclass that returns deterministic labels based on temp file content."""
        tmp_file = args[0][2]  # ["avclass", "-f", "<tmp_path>"]
        content = Path(tmp_file).read_text(encoding="utf-8")
        data = json.loads(content)
        file_id = data.get("data", {}).get("id", "unknown")

        label_map = {
            "275a021b": "eicar",
            "bbbbbbbb": "trojan",
            "cccccccc": "ransomware",
        }
        label = "unknown"
        for prefix, lbl in label_map.items():
            if file_id.startswith(prefix):
                label = lbl
                break

        mock_result = MagicMock()
        mock_result.stdout = f"filename\t{label}\n"
        return mock_result

    def test_csv_header_and_row_count(self, populated_tmp_dir):
        labeler = _make_labeler(populated_tmp_dir["root"])
        labeler._collect_files()

        with patch("avclass_label.labeler.subprocess.run", side_effect=self._mock_subprocess):
            labeler._label_all()

        with labeler.config.output_path.open(encoding="utf-8") as f:
            rows = list(csv.reader(f))

        assert rows[0] == ["fileName", "label"]
        # 3 valid + 1 invalid = 4 files
        assert len(rows) == 5

    def test_rows_sorted_by_filename(self, populated_tmp_dir):
        labeler = _make_labeler(populated_tmp_dir["root"])
        labeler._collect_files()

        with patch("avclass_label.labeler.subprocess.run", side_effect=self._mock_subprocess):
            labeler._label_all()

        with labeler.config.output_path.open(encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader)
            names = [row[0] for row in reader]

        assert names == sorted(names)

    def test_invalid_json_gets_error_label(self, populated_tmp_dir):
        labeler = _make_labeler(populated_tmp_dir["root"])
        labeler._collect_files()

        with patch("avclass_label.labeler.subprocess.run", side_effect=self._mock_subprocess):
            labeler._label_all()

        with labeler.config.output_path.open(encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = {row["fileName"]: row["label"] for row in reader}

        assert rows["bad_report"] == "Error"

    def test_empty_directory_produces_header_only(self, tmp_path):
        labeler = _make_labeler(tmp_path)
        labeler._collect_files()
        labeler._label_all()

        with labeler.config.output_path.open(encoding="utf-8") as f:
            content = f.read()

        # csv.writer adds \r\n on some platforms, so just check header presence
        assert content.startswith("fileName,label")


# ===================================================================
# CLI
# ===================================================================


class TestCli:
    """Test CLI argument parsing."""

    def test_input_folder_required(self):
        from avclass_label.cli import parse_args

        with pytest.raises(SystemExit):
            parse_args([])

    def test_parse_input_folder(self):
        from avclass_label.cli import parse_args

        args = parse_args(["-i", "/some/path"])
        assert args.input_folder == "/some/path"

    def test_parse_max_workers(self):
        from avclass_label.cli import parse_args

        args = parse_args(["-i", "/some/path", "-w", "8"])
        assert args.max_workers == 8

    def test_verbose_default_false(self):
        from avclass_label.cli import parse_args

        args = parse_args(["-i", "/some/path"])
        assert args.verbose is False

    def test_verbose_flag(self):
        from avclass_label.cli import parse_args

        args = parse_args(["-i", "/some/path", "-v"])
        assert args.verbose is True
