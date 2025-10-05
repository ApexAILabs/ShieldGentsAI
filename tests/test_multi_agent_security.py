"""Tests for multi-agent coordination security module."""

import pytest
from shieldgents.integrations.multi_agent_security import (
    AgentRegistry,
    SecureMessageBus,
    ConsensusEngine,
    ByzantineDetector,
    TrustLevel,
    MessageType,
    ConsensusType,
)


class TestAgentRegistry:
    """Test agent registry functionality."""

    def test_register_agent(self):
        """Test agent registration."""
        registry = AgentRegistry()

        agent = registry.register_agent(
            "agent-1",
            trust_level=TrustLevel.HIGH,
            capabilities={"read", "write"}
        )

        assert agent.agent_id == "agent-1"
        assert agent.trust_level == TrustLevel.HIGH
        assert "read" in agent.capabilities

    def test_duplicate_registration(self):
        """Test that duplicate registration fails."""
        registry = AgentRegistry()

        registry.register_agent("agent-1")

        with pytest.raises(ValueError):
            registry.register_agent("agent-1")

    def test_get_agent(self):
        """Test retrieving agent."""
        registry = AgentRegistry()
        registry.register_agent("agent-1", trust_level=TrustLevel.MEDIUM)

        agent = registry.get_agent("agent-1")

        assert agent is not None
        assert agent.trust_level == TrustLevel.MEDIUM

    def test_set_trust(self):
        """Test setting trust between agents."""
        registry = AgentRegistry()
        registry.register_agent("agent-1")
        registry.register_agent("agent-2")

        registry.set_trust("agent-1", "agent-2", TrustLevel.HIGH)

        trust = registry.get_trust("agent-1", "agent-2")
        assert trust == TrustLevel.HIGH

    def test_is_authorized(self):
        """Test capability authorization."""
        registry = AgentRegistry()
        registry.register_agent("agent-1", capabilities={"read", "write"})

        assert registry.is_authorized("agent-1", "read") is True
        assert registry.is_authorized("agent-1", "delete") is False


class TestSecureMessageBus:
    """Test secure message bus."""

    def test_send_message(self):
        """Test sending a message."""
        registry = AgentRegistry()
        registry.register_agent("sender")
        registry.register_agent("receiver")

        bus = SecureMessageBus(registry)

        message = bus.send_message(
            sender_id="sender",
            receiver_id="receiver",
            message_type=MessageType.REQUEST,
            payload={"data": "test"}
        )

        assert message is not None
        assert message.sender_id == "sender"
        assert message.receiver_id == "receiver"

    def test_broadcast_message(self):
        """Test broadcasting a message."""
        registry = AgentRegistry()
        registry.register_agent("sender")
        registry.register_agent("receiver1")
        registry.register_agent("receiver2")

        bus = SecureMessageBus(registry)

        message = bus.send_message(
            sender_id="sender",
            receiver_id=None,  # Broadcast
            message_type=MessageType.BROADCAST,
            payload={"data": "broadcast"}
        )

        assert message is not None
        assert message.receiver_id is None

    def test_message_signing(self):
        """Test message signing."""
        registry = AgentRegistry()
        registry.register_agent("sender")
        registry.register_agent("receiver")

        bus = SecureMessageBus(registry)

        message = bus.send_message(
            sender_id="sender",
            receiver_id="receiver",
            message_type=MessageType.REQUEST,
            payload={"data": "test"},
            sign=True
        )

        assert message.signature is not None
        assert bus.verify_message(message) is True

    def test_message_subscription(self):
        """Test message subscription."""
        registry = AgentRegistry()
        registry.register_agent("sender")
        registry.register_agent("receiver")

        bus = SecureMessageBus(registry)

        received_messages = []

        def callback(msg):
            received_messages.append(msg)

        bus.subscribe("receiver", callback)

        bus.send_message(
            sender_id="sender",
            receiver_id="receiver",
            message_type=MessageType.REQUEST,
            payload={"data": "test"}
        )

        assert len(received_messages) == 1
        assert received_messages[0].sender_id == "sender"


class TestConsensusEngine:
    """Test consensus mechanisms."""

    def test_create_proposal(self):
        """Test creating a proposal."""
        registry = AgentRegistry()
        registry.register_agent("proposer")

        engine = ConsensusEngine(registry)

        success = engine.create_proposal(
            proposal_id="prop-1",
            proposer_id="proposer",
            proposal_data={"action": "upgrade"},
            consensus_type=ConsensusType.SIMPLE_MAJORITY
        )

        assert success is True
        assert "prop-1" in engine.proposals

    def test_cast_vote(self):
        """Test casting a vote."""
        registry = AgentRegistry()
        registry.register_agent("proposer")
        registry.register_agent("voter")

        engine = ConsensusEngine(registry)

        engine.create_proposal(
            proposal_id="prop-1",
            proposer_id="proposer",
            proposal_data={"action": "upgrade"}
        )

        success = engine.cast_vote("prop-1", "voter", vote=True)

        assert success is True

    def test_simple_majority_consensus(self):
        """Test simple majority consensus."""
        registry = AgentRegistry()
        for i in range(5):
            registry.register_agent(f"agent-{i}")

        engine = ConsensusEngine(registry)

        engine.create_proposal(
            proposal_id="prop-1",
            proposer_id="agent-0",
            proposal_data={"action": "test"},
            consensus_type=ConsensusType.SIMPLE_MAJORITY
        )

        # Cast 3 yes votes out of 5
        engine.cast_vote("prop-1", "agent-0", True)
        engine.cast_vote("prop-1", "agent-1", True)
        engine.cast_vote("prop-1", "agent-2", True)

        result = engine.check_consensus("prop-1")

        assert result is True

    def test_unanimous_consensus(self):
        """Test unanimous consensus."""
        registry = AgentRegistry()
        for i in range(3):
            registry.register_agent(f"agent-{i}")

        engine = ConsensusEngine(registry)

        engine.create_proposal(
            proposal_id="prop-1",
            proposer_id="agent-0",
            proposal_data={"action": "test"},
            consensus_type=ConsensusType.UNANIMOUS
        )

        # All vote yes
        engine.cast_vote("prop-1", "agent-0", True)
        engine.cast_vote("prop-1", "agent-1", True)
        engine.cast_vote("prop-1", "agent-2", True)

        result = engine.check_consensus("prop-1")

        assert result is True

    def test_unanimous_consensus_fails(self):
        """Test unanimous consensus fails with one no vote."""
        registry = AgentRegistry()
        for i in range(3):
            registry.register_agent(f"agent-{i}")

        engine = ConsensusEngine(registry)

        engine.create_proposal(
            proposal_id="prop-1",
            proposer_id="agent-0",
            proposal_data={"action": "test"},
            consensus_type=ConsensusType.UNANIMOUS
        )

        # One no vote
        engine.cast_vote("prop-1", "agent-0", True)
        engine.cast_vote("prop-1", "agent-1", True)
        engine.cast_vote("prop-1", "agent-2", False)

        result = engine.check_consensus("prop-1")

        assert result is False

    def test_bft_consensus(self):
        """Test Byzantine fault tolerant consensus."""
        registry = AgentRegistry()
        for i in range(10):
            registry.register_agent(f"agent-{i}")

        engine = ConsensusEngine(registry)

        engine.create_proposal(
            proposal_id="prop-1",
            proposer_id="agent-0",
            proposal_data={"action": "test"},
            consensus_type=ConsensusType.BYZANTINE_FAULT_TOLERANT
        )

        # BFT requires 2f+1 votes where f=(n-1)/3
        # With 10 agents, f=3, so need 7 votes
        for i in range(7):
            engine.cast_vote("prop-1", f"agent-{i}", True)

        result = engine.check_consensus("prop-1")

        assert result is True


class TestByzantineDetector:
    """Test Byzantine agent detection."""

    def test_record_behavior(self):
        """Test recording agent behavior."""
        registry = AgentRegistry()
        registry.register_agent("agent-1")

        detector = ByzantineDetector(registry)

        detector.record_behavior("agent-1", "sent malicious message", is_malicious=True)

        reputation = detector.get_reputation("agent-1")

        # Reputation should decrease
        assert reputation < 1.0

    def test_is_byzantine(self):
        """Test Byzantine detection."""
        registry = AgentRegistry()
        registry.register_agent("agent-1")

        detector = ByzantineDetector(registry)

        # Record multiple malicious behaviors
        for _ in range(10):
            detector.record_behavior("agent-1", "malicious action", is_malicious=True)

        is_byz = detector.is_byzantine("agent-1", threshold=0.5)

        assert is_byz is True

    def test_reputation_recovery(self):
        """Test that good behavior improves reputation."""
        registry = AgentRegistry()
        registry.register_agent("agent-1")

        detector = ByzantineDetector(registry)

        # One bad behavior
        detector.record_behavior("agent-1", "bad", is_malicious=True)
        reputation_after_bad = detector.get_reputation("agent-1")

        # Many good behaviors
        for _ in range(20):
            detector.record_behavior("agent-1", "good", is_malicious=False)

        reputation_after_good = detector.get_reputation("agent-1")

        # Reputation should improve
        assert reputation_after_good > reputation_after_bad
