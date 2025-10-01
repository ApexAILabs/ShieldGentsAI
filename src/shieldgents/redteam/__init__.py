"""Red-team utilities for probing agent security."""

from shieldgents.redteam import vectors, exfiltration, covert_channel
from shieldgents.redteam.covert_channel import (
    CovertChannelDetection,
    CovertChannelDetector,
    CovertChannelType,
)
from shieldgents.redteam.exfiltration import (
    ExfiltrationDetection,
    ExfiltrationDetector,
    ExfiltrationMethod,
)
from shieldgents.redteam.vectors import (
    AttackCategory,
    AttackVector,
    AttackVectorLibrary,
    FuzzTester,
    RedTeamTester,
)

__all__ = [
    "vectors",
    "exfiltration",
    "covert_channel",
    "CovertChannelDetection",
    "CovertChannelDetector",
    "CovertChannelType",
    "ExfiltrationDetection",
    "ExfiltrationDetector",
    "ExfiltrationMethod",
    "AttackCategory",
    "AttackVector",
    "AttackVectorLibrary",
    "FuzzTester",
    "RedTeamTester",
]
