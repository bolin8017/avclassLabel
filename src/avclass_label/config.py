"""Configuration for AVClass labeling."""

from __future__ import annotations

from pathlib import Path


class Config:
    """Holds validated paths and tuning knobs for the labeler."""

    input_dir: Path
    output_path: Path
    max_workers: int | None

    def __init__(
        self,
        input_dir: str | Path,
        max_workers: int | None = None,
    ) -> None:
        self.input_dir = Path(input_dir)
        if not self.input_dir.is_dir():
            raise ValueError(f"Input path is not an existing directory: {self.input_dir}")
        self.output_path = self.input_dir / "label.csv"
        self.max_workers = max_workers
