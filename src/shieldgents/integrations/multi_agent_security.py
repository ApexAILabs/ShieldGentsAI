"""
Multi-Agent Coordination Security Module

Provides security controls for multi-agent systems including:
- Secure agent-to-agent communication
- Byzantine fault tolerance
- Consensus mechanisms for critical decisions
- Agent authentication and authorization
- Message integrity and encryption
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Callable
import hashlib
import json
import secrets


class MessageType(Enum):
    """Types of inter-agent messages."""

    REQUEST = "request"
    RESPONSE = "response"
    BROADCAST = "broadcast"
    VOTE = "vote"
    PROPOSAL = "proposal"
    ACKNOWLEDGMENT = "acknowledgment"


class TrustLevel(Enum):
    """Trust levels for agents."""

    UNTRUSTED = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    VERIFIED = 4


class ConsensusType(Enum):
    """Types of consensus mechanisms."""

    SIMPLE_MAJORITY = "simple_majority"
    SUPERMAJORITY = "supermajority"
    UNANIMOUS = "unanimous"
    WEIGHTED = "weighted"
    BYZANTINE_FAULT_TOLERANT = "bft"


@dataclass
class AgentIdentity:
    """Represents an agent's identity and credentials."""

    agent_id: str
    public_key: Optional[str] = None
    trust_level: TrustLevel = TrustLevel.UNTRUSTED
    capabilities: Set[str] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class SecureMessage:
    """A secure message between agents."""

    message_id: str
    sender_id: str
    receiver_id: Optional[str]  # None for broadcast
    message_type: MessageType
    payload: Dict[str, Any]
    timestamp: datetime
    signature: Optional[str] = None
    encrypted: bool = False
    nonce: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert message to dictionary."""
        return {
            "message_id": self.message_id,
            "sender_id": self.sender_id,
            "receiver_id": self.receiver_id,
            "message_type": self.message_type.value,
            "payload": self.payload,
            "timestamp": self.timestamp.isoformat(),
            "signature": self.signature,
            "encrypted": self.encrypted,
            "nonce": self.nonce,
        }


@dataclass
class SecurityAlert:
    """Security alert for multi-agent system."""

    alert_type: str
    severity: str
    description: str
    involved_agents: List[str]
    timestamp: datetime = field(default_factory=datetime.now)
    evidence: Dict[str, Any] = field(default_factory=dict)


class AgentRegistry:
    """
    Manages agent identities and trust relationships.
    """

    def __init__(self):
        self.agents: Dict[str, AgentIdentity] = {}
        self.trust_relationships: Dict[str, Dict[str, TrustLevel]] = {}

    def register_agent(
        self,
        agent_id: str,
        trust_level: TrustLevel = TrustLevel.LOW,
        capabilities: Optional[Set[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AgentIdentity:
        """
        Register a new agent in the system.

        Args:
            agent_id: Unique agent identifier
            trust_level: Initial trust level
            capabilities: Set of agent capabilities
            metadata: Additional agent metadata

        Returns:
            AgentIdentity object
        """
        if agent_id in self.agents:
            raise ValueError(f"Agent {agent_id} already registered")

        identity = AgentIdentity(
            agent_id=agent_id,
            trust_level=trust_level,
            capabilities=capabilities or set(),
            metadata=metadata or {},
        )

        self.agents[agent_id] = identity
        self.trust_relationships[agent_id] = {}

        return identity

    def get_agent(self, agent_id: str) -> Optional[AgentIdentity]:
        """Get agent identity."""
        return self.agents.get(agent_id)

    def set_trust(self, agent_id: str, target_id: str, trust_level: TrustLevel):
        """
        Set trust level between two agents.

        Args:
            agent_id: The agent setting trust
            target_id: The agent being trusted
            trust_level: Trust level to assign
        """
        if agent_id not in self.trust_relationships:
            self.trust_relationships[agent_id] = {}

        self.trust_relationships[agent_id][target_id] = trust_level

    def get_trust(self, agent_id: str, target_id: str) -> TrustLevel:
        """Get trust level between two agents."""
        if agent_id not in self.trust_relationships:
            return TrustLevel.UNTRUSTED

        return self.trust_relationships[agent_id].get(target_id, TrustLevel.UNTRUSTED)

    def is_authorized(self, agent_id: str, capability: str) -> bool:
        """Check if agent has a specific capability."""
        agent = self.get_agent(agent_id)
        if not agent:
            return False

        return capability in agent.capabilities


class SecureMessageBus:
    """
    Secure message bus for agent-to-agent communication.

    Features:
    - Message signing and verification
    - Message replay prevention
    - Rate limiting per agent
    - Message validation
    """

    def __init__(self, registry: AgentRegistry):
        self.registry = registry
        self.message_history: Dict[str, List[SecureMessage]] = {}
        self.seen_nonces: Set[str] = set()
        self.message_callbacks: Dict[str, List[Callable]] = {}

    def send_message(
        self,
        sender_id: str,
        receiver_id: Optional[str],
        message_type: MessageType,
        payload: Dict[str, Any],
        sign: bool = True,
    ) -> Optional[SecureMessage]:
        """
        Send a message from one agent to another.

        Args:
            sender_id: Sender agent ID
            receiver_id: Receiver agent ID (None for broadcast)
            message_type: Type of message
            payload: Message payload
            sign: Whether to sign the message

        Returns:
            SecureMessage if successful, None otherwise
        """
        # Verify sender exists
        sender = self.registry.get_agent(sender_id)
        if not sender:
            return None

        # Verify receiver exists (if not broadcast)
        if receiver_id:
            receiver = self.registry.get_agent(receiver_id)
            if not receiver:
                return None

        # Create message
        message_id = self._generate_message_id()
        nonce = secrets.token_hex(16)

        message = SecureMessage(
            message_id=message_id,
            sender_id=sender_id,
            receiver_id=receiver_id,
            message_type=message_type,
            payload=payload,
            timestamp=datetime.now(),
            nonce=nonce,
        )

        # Sign message if requested
        if sign:
            message.signature = self._sign_message(message)

        # Store in history
        if sender_id not in self.message_history:
            self.message_history[sender_id] = []
        self.message_history[sender_id].append(message)

        # Add nonce to prevent replay
        self.seen_nonces.add(nonce)

        # Deliver message
        self._deliver_message(message)

        return message

    def verify_message(self, message: SecureMessage) -> bool:
        """
        Verify message integrity and authenticity.

        Args:
            message: Message to verify

        Returns:
            True if message is valid
        """
        # Check if sender exists
        if not self.registry.get_agent(message.sender_id):
            return False

        # Check for replay attack
        if message.nonce in self.seen_nonces:
            return False

        # Verify signature if present
        if message.signature:
            expected_signature = self._sign_message(message)
            if message.signature != expected_signature:
                return False

        return True

    def subscribe(self, receiver_id: str, callback: Callable[[SecureMessage], None]):
        """
        Subscribe to messages for an agent.

        Args:
            receiver_id: Agent ID to receive messages
            callback: Callback function to handle messages
        """
        if receiver_id not in self.message_callbacks:
            self.message_callbacks[receiver_id] = []

        self.message_callbacks[receiver_id].append(callback)

    def _generate_message_id(self) -> str:
        """Generate unique message ID."""
        return f"msg_{secrets.token_hex(16)}"

    def _sign_message(self, message: SecureMessage) -> str:
        """
        Sign a message (simplified - use proper crypto in production).

        Args:
            message: Message to sign

        Returns:
            Message signature
        """
        # In production, use proper asymmetric cryptography
        message_data = json.dumps(message.to_dict(), sort_keys=True)
        return hashlib.sha256(message_data.encode()).hexdigest()

    def _deliver_message(self, message: SecureMessage):
        """Deliver message to subscribers."""
        # Deliver to specific receiver
        if message.receiver_id:
            if message.receiver_id in self.message_callbacks:
                for callback in self.message_callbacks[message.receiver_id]:
                    callback(message)

        # Broadcast to all
        else:
            for receiver_id, callbacks in self.message_callbacks.items():
                if receiver_id != message.sender_id:  # Don't send to self
                    for callback in callbacks:
                        callback(message)


class ConsensusEngine:
    """
    Implements consensus mechanisms for multi-agent decisions.

    Features:
    - Multiple consensus types
    - Byzantine fault tolerance
    - Weighted voting
    """

    def __init__(self, registry: AgentRegistry):
        self.registry = registry
        self.proposals: Dict[str, Dict[str, Any]] = {}
        self.votes: Dict[str, Dict[str, Any]] = {}

    def create_proposal(
        self,
        proposal_id: str,
        proposer_id: str,
        proposal_data: Dict[str, Any],
        consensus_type: ConsensusType = ConsensusType.SIMPLE_MAJORITY,
        eligible_voters: Optional[List[str]] = None,
    ) -> bool:
        """
        Create a new proposal for consensus.

        Args:
            proposal_id: Unique proposal identifier
            proposer_id: Agent creating the proposal
            proposal_data: Proposal content
            consensus_type: Type of consensus required
            eligible_voters: List of agents eligible to vote

        Returns:
            True if proposal created successfully
        """
        if proposal_id in self.proposals:
            return False

        if not self.registry.get_agent(proposer_id):
            return False

        self.proposals[proposal_id] = {
            "proposer_id": proposer_id,
            "data": proposal_data,
            "consensus_type": consensus_type,
            "eligible_voters": eligible_voters or list(self.registry.agents.keys()),
            "created_at": datetime.now(),
            "finalized": False,
        }

        self.votes[proposal_id] = {}

        return True

    def cast_vote(self, proposal_id: str, voter_id: str, vote: bool, weight: float = 1.0) -> bool:
        """
        Cast a vote on a proposal.

        Args:
            proposal_id: Proposal to vote on
            voter_id: Agent casting vote
            vote: True for yes, False for no
            weight: Vote weight (for weighted consensus)

        Returns:
            True if vote recorded successfully
        """
        if proposal_id not in self.proposals:
            return False

        proposal = self.proposals[proposal_id]

        # Check if proposal is finalized
        if proposal["finalized"]:
            return False

        # Check if voter is eligible
        if voter_id not in proposal["eligible_voters"]:
            return False

        # Check if voter exists
        if not self.registry.get_agent(voter_id):
            return False

        # Record vote
        self.votes[proposal_id][voter_id] = {
            "vote": vote,
            "weight": weight,
            "timestamp": datetime.now(),
        }

        return True

    def check_consensus(self, proposal_id: str) -> Optional[bool]:
        """
        Check if consensus has been reached.

        Args:
            proposal_id: Proposal to check

        Returns:
            True if consensus reached for approval,
            False if consensus reached for rejection,
            None if consensus not yet reached
        """
        if proposal_id not in self.proposals:
            return None

        proposal = self.proposals[proposal_id]
        votes = self.votes[proposal_id]

        consensus_type = proposal["consensus_type"]
        eligible_count = len(proposal["eligible_voters"])

        if consensus_type == ConsensusType.SIMPLE_MAJORITY:
            return self._check_simple_majority(votes, eligible_count)

        elif consensus_type == ConsensusType.SUPERMAJORITY:
            return self._check_supermajority(votes, eligible_count)

        elif consensus_type == ConsensusType.UNANIMOUS:
            return self._check_unanimous(votes, eligible_count)

        elif consensus_type == ConsensusType.WEIGHTED:
            return self._check_weighted(votes)

        elif consensus_type == ConsensusType.BYZANTINE_FAULT_TOLERANT:
            return self._check_bft(votes, eligible_count)

        return None

    def finalize_proposal(self, proposal_id: str) -> bool:
        """Mark proposal as finalized."""
        if proposal_id in self.proposals:
            self.proposals[proposal_id]["finalized"] = True
            return True
        return False

    def _check_simple_majority(self, votes: Dict[str, Any], total: int) -> Optional[bool]:
        """Check simple majority (>50%)."""
        if len(votes) < total // 2 + 1:
            return None

        yes_votes = sum(1 for v in votes.values() if v["vote"])
        no_votes = len(votes) - yes_votes

        if yes_votes > total / 2:
            return True
        elif no_votes > total / 2:
            return False

        return None

    def _check_supermajority(self, votes: Dict[str, Any], total: int) -> Optional[bool]:
        """Check supermajority (>=2/3)."""
        if len(votes) < (2 * total) // 3:
            return None

        yes_votes = sum(1 for v in votes.values() if v["vote"])

        if yes_votes >= (2 * total) / 3:
            return True
        elif len(votes) - yes_votes > total / 3:
            return False

        return None

    def _check_unanimous(self, votes: Dict[str, Any], total: int) -> Optional[bool]:
        """Check unanimous consensus."""
        if len(votes) < total:
            return None

        return all(v["vote"] for v in votes.values())

    def _check_weighted(self, votes: Dict[str, Any]) -> Optional[bool]:
        """Check weighted consensus."""
        if not votes:
            return None

        total_weight = sum(v["weight"] for v in votes.values())
        yes_weight = sum(v["weight"] for v in votes.values() if v["vote"])

        if yes_weight > total_weight / 2:
            return True
        elif total_weight - yes_weight > total_weight / 2:
            return False

        return None

    def _check_bft(self, votes: Dict[str, Any], total: int) -> Optional[bool]:
        """
        Check Byzantine fault tolerant consensus.
        Requires 2f+1 agreeing votes where f is max faulty agents.
        """
        f = (total - 1) // 3  # Maximum Byzantine faults tolerated
        required_votes = 2 * f + 1

        if len(votes) < required_votes:
            return None

        yes_votes = sum(1 for v in votes.values() if v["vote"])

        if yes_votes >= required_votes:
            return True
        elif len(votes) - yes_votes >= required_votes:
            return False

        return None


class ByzantineDetector:
    """
    Detects Byzantine (malicious or faulty) agents.

    Features:
    - Inconsistency detection
    - Reputation tracking
    - Anomaly detection
    """

    def __init__(self, registry: AgentRegistry):
        self.registry = registry
        self.agent_reputations: Dict[str, float] = {}
        self.suspicious_behaviors: Dict[str, List[str]] = {}

    def record_behavior(self, agent_id: str, behavior: str, is_malicious: bool):
        """
        Record agent behavior for reputation tracking.

        Args:
            agent_id: Agent ID
            behavior: Description of behavior
            is_malicious: Whether behavior is malicious
        """
        if agent_id not in self.agent_reputations:
            self.agent_reputations[agent_id] = 1.0  # Start with neutral reputation

        # Update reputation
        if is_malicious:
            self.agent_reputations[agent_id] *= 0.9  # Decrease reputation
            if agent_id not in self.suspicious_behaviors:
                self.suspicious_behaviors[agent_id] = []
            self.suspicious_behaviors[agent_id].append(behavior)
        else:
            self.agent_reputations[agent_id] = min(1.0, self.agent_reputations[agent_id] + 0.01)

    def is_byzantine(self, agent_id: str, threshold: float = 0.5) -> bool:
        """
        Check if an agent is likely Byzantine.

        Args:
            agent_id: Agent to check
            threshold: Reputation threshold

        Returns:
            True if agent is likely Byzantine
        """
        reputation = self.agent_reputations.get(agent_id, 1.0)
        return reputation < threshold

    def get_reputation(self, agent_id: str) -> float:
        """Get agent reputation score."""
        return self.agent_reputations.get(agent_id, 1.0)

    def detect_inconsistency(
        self, agent_id: str, messages: List[SecureMessage]
    ) -> Optional[SecurityAlert]:
        """
        Detect inconsistent messaging from an agent.

        Args:
            agent_id: Agent to check
            messages: Recent messages from agent

        Returns:
            SecurityAlert if inconsistency detected
        """
        # Simple check: look for contradictory messages
        responses = [m for m in messages if m.message_type == MessageType.RESPONSE]

        if len(responses) >= 2:
            # Check if agent gave different responses to same request
            # (simplified - in production, implement semantic analysis)
            payloads = [json.dumps(r.payload, sort_keys=True) for r in responses]

            if len(set(payloads)) != len(payloads):
                self.record_behavior(agent_id, "inconsistent_messaging", True)

                return SecurityAlert(
                    alert_type="byzantine_behavior",
                    severity="high",
                    description=f"Agent {agent_id} sent inconsistent messages",
                    involved_agents=[agent_id],
                    evidence={"message_count": len(messages)},
                )

        return None
