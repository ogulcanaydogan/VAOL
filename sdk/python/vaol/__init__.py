"""VAOL — Verifiable AI Output Ledger Python SDK.

Provides instrumentation wrappers for LLM client libraries that automatically
emit cryptographically verifiable decision records to a VAOL server.
"""

from vaol.client import AsyncVAOLClient, VAOLClient
from vaol.record import DecisionRecord, OutputMode, PolicyDecision
from vaol.verify import VerifyResult, verify_dsse_ed25519, verify_inclusion_proof
from vaol.wrapper import instrument_openai

__version__ = "0.3.0"
__all__ = [
    "AsyncVAOLClient",
    "DecisionRecord",
    "OutputMode",
    "PolicyDecision",
    "VAOLClient",
    "VerifyResult",
    "instrument_openai",
    "verify_dsse_ed25519",
    "verify_inclusion_proof",
]
