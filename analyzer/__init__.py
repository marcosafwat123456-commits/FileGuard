"""FileGuard Analyzer Package.
Static heuristic analysis engine for suspicious file triage.
Never executes analyzed files.
"""

from .core import FileAnalyzer

__all__ = ['FileAnalyzer']
