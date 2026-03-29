"""avclass_label -- classify malware families from VirusTotal JSON reports."""

from avclass_label.config import Config
from avclass_label.labeler import Labeler

__all__ = ["Config", "Labeler"]
