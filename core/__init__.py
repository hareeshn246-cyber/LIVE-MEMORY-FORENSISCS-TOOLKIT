"""
Core Module - Windows Memory Forensics Foundation
Handles low-level memory acquisition, integrity validation, and evidence lifecycle
"""

from .acquisition import MemoryAcquisition
from .integrity import HookDetector
from .lifecycle import EvidenceManager

__all__ = ['MemoryAcquisition', 'HookDetector', 'EvidenceManager']
