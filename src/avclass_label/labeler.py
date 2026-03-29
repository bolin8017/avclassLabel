"""Core labeling logic: scan directories, invoke avclass, write CSV."""

from __future__ import annotations

import csv
import json
import logging
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from tqdm import tqdm

from avclass_label.config import Config

logger = logging.getLogger(__name__)

_ERROR_LABEL = "Error"


class Labeler:
    """Scans a directory of VirusTotal JSON reports and labels them via avclass."""

    def __init__(self, config: Config) -> None:
        self.config = config

    def run(self) -> Path:
        """Execute the full labeling pipeline. Returns the output CSV path."""
        files = self._collect_files()
        self._label_all(files)
        logger.info("Output label.csv path: %s", self.config.output_path.resolve())
        return self.config.output_path

    def _collect_files(self) -> list[Path]:
        files = sorted(self.config.input_dir.rglob("*.json"))
        logger.info("Found %d JSON files.", len(files))
        return files

    @staticmethod
    def _convert_to_one_line(json_path: Path) -> str | None:
        """Read a JSON file and return its compact single-line representation."""
        try:
            data = json.loads(json_path.read_text(encoding="utf-8"))
            return json.dumps(data, separators=(",", ":"))
        except json.JSONDecodeError:
            logger.warning("Invalid JSON in %s", json_path)
            return None
        except OSError as exc:
            logger.warning("Cannot read %s: %s", json_path, exc)
            return None

    @staticmethod
    def _process_json(json_path: Path) -> tuple[str, str]:
        """Label a single JSON report via the avclass CLI.

        Returns ``(stem, label)`` where *label* is ``"Error"`` on failure.
        """
        file_name = json_path.stem

        one_line_data = Labeler._convert_to_one_line(json_path)
        if one_line_data is None:
            return file_name, _ERROR_LABEL

        tmp_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".jsonl",
                encoding="utf-8",
                delete=False,
            ) as tmp_file:
                tmp_file.write(one_line_data)
                tmp_path = Path(tmp_file.name)

            result = subprocess.run(
                ["avclass", "-f", str(tmp_path)],
                check=True,
                text=True,
                capture_output=True,
            )
            first_line = result.stdout.splitlines()[0]
            label = first_line.split("\t")[1].strip()
        except subprocess.CalledProcessError:
            logger.error("avclass failed for %s", json_path)
            label = _ERROR_LABEL
        except (IndexError, ValueError):
            logger.error("Unexpected avclass output for %s", json_path)
            label = _ERROR_LABEL
        except OSError as exc:
            logger.error("OS error processing %s: %s", json_path, exc)
            label = _ERROR_LABEL
        finally:
            if tmp_path is not None:
                tmp_path.unlink(missing_ok=True)

        return file_name, label

    def _label_all(self, files: list[Path]) -> None:
        start_time = time.monotonic()
        labels: list[tuple[str, str]] = []

        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            futures = {executor.submit(self._process_json, p): p for p in files}
            for future in tqdm(
                as_completed(futures),
                total=len(futures),
                desc="Labeling",
                unit="file",
            ):
                file_name, label = future.result()
                labels.append((file_name, label))

        labels.sort(key=lambda pair: pair[0])

        with self.config.output_path.open("w", encoding="utf-8", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["fileName", "label"])
            writer.writerows(labels)

        elapsed = time.monotonic() - start_time
        logger.info("Labeled %d files in %.2f seconds.", len(labels), elapsed)
