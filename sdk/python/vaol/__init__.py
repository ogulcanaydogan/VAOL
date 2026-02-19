"""VAOL — Verifiable AI Output Ledger Python SDK.

Provides instrumentation wrappers for LLM client libraries that automatically
emit cryptographically verifiable decision records to a VAOL server.
"""

from vaol.client import VAOLClient
from vaol.record import DecisionRecord, OutputMode, PolicyDecision
from vaol.wrapper import instrument_openai

__version__ = "0.1.0"
__all__ = [
    "VAOLClient",
    "DecisionRecord",
    "OutputMode",
    "PolicyDecision",
    "instrument_openai",
]
