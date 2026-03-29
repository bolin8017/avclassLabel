"""Tests for the Config class."""

from pathlib import Path

import pytest

from avclass_label.config import Config


class TestConfigInit:
    """Config should validate input_dir and derive output_path."""

    def test_basic_directory(self, tmp_path):
        cfg = Config(str(tmp_path))
        assert cfg.output_path == tmp_path / "label.csv"

    def test_accepts_path_object(self, tmp_path):
        cfg = Config(tmp_path)
        assert cfg.input_dir == tmp_path

    def test_nested_directory(self, tmp_path):
        nested = tmp_path / "a" / "b" / "c"
        nested.mkdir(parents=True)
        cfg = Config(nested)
        assert cfg.output_path == nested / "label.csv"

    def test_nonexistent_directory_raises(self):
        with pytest.raises(ValueError, match="not an existing directory"):
            Config("/nonexistent/path/that/does/not/exist")

    def test_file_path_raises(self, tmp_path):
        f = tmp_path / "file.txt"
        f.write_text("hello")
        with pytest.raises(ValueError):
            Config(f)

    def test_max_workers_default_none(self, tmp_path):
        cfg = Config(tmp_path)
        assert cfg.max_workers is None

    def test_max_workers_custom(self, tmp_path):
        cfg = Config(tmp_path, max_workers=4)
        assert cfg.max_workers == 4

    def test_input_dir_is_path(self, tmp_path):
        cfg = Config(str(tmp_path))
        assert isinstance(cfg.input_dir, Path)
