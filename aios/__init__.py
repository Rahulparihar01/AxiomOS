"""
AxiomOS: The Deterministic Control Plane for Autonomous Agents.
"""

from config.settings import settings
from kernel import Kernel, PriorityLevel, ProcessControlBlock, ProcessState, ResourceGovernor
from kernel.checkpoint import CheckpointManager
from kernel.flight_recorder import FlightRecorder
from kernel.replay import TraceReplayEngine, ReplayReport
from security.capability import CapabilityIssuer, CapabilityToken
from security.rings import SecurityRing
from security.hitl import HITLManager
from security.vault import SecretsVault
from aios.client import AIOSClient

AxiomClient = AIOSClient

__version__ = settings.version
__all__ = [
    "Kernel",
    "ProcessControlBlock",
    "ProcessState",
    "PriorityLevel",
    "ResourceGovernor",
    "CheckpointManager",
    "FlightRecorder",
    "TraceReplayEngine",
    "ReplayReport",
    "CapabilityIssuer",
    "CapabilityToken",
    "SecurityRing",
    "HITLManager",
    "SecretsVault",
    "AxiomClient",
    "AIOSClient",
    "settings",
    "__version__",
]
