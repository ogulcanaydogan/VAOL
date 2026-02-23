"""VAOL — Verifiable AI Output Ledger Python SDK.

Provides instrumentation wrappers for LLM client libraries that automatically
emit cryptographically verifiable decision records to a VAOL server.
"""

from vaol.anthropic_wrapper import instrument_anthropic
from vaol.client import AsyncVAOLClient, VAOLClient
from vaol.litellm_wrapper import instrument_litellm
from vaol.record import DecisionRecord, OutputMode, PolicyDecision
from vaol.verify import VerifyResult, verify_dsse_ed25519, verify_inclusion_proof
from vaol.wrapper import instrument_openai

__version__ = "0.2.24"
__all__ = [
    "AsyncVAOLClient",
    "DecisionRecord",
    "OutputMode",
    "PolicyDecision",
    "VAOLClient",
    "VerifyResult",
    "instrument_anthropic",
    "instrument_litellm",
    "instrument_openai",
    "verify_dsse_ed25519",
    "verify_inclusion_proof",
]
