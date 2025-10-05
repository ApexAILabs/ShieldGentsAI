"""
Hallucination Detection Module

Detects and mitigates hallucinations in AI agent outputs including:
- Fact-checking against knowledge bases
- Consistency checking across responses
- Confidence scoring for outputs
- Citation and source validation
- Temporal consistency checking
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Callable
import re
import hashlib


class HallucinationType(Enum):
    """Types of hallucinations."""
    FACTUAL_ERROR = "factual_error"
    INCONSISTENCY = "inconsistency"
    UNSUPPORTED_CLAIM = "unsupported_claim"
    TEMPORAL_INCONSISTENCY = "temporal_inconsistency"
    FABRICATED_SOURCE = "fabricated_source"
    CONTRADICTORY_STATEMENT = "contradictory_statement"
    LOW_CONFIDENCE = "low_confidence"


@dataclass
class HallucinationAlert:
    """Alert for detected hallucination."""
    hallucination_type: HallucinationType
    severity: str  # "low", "medium", "high", "critical"
    confidence: float  # How confident we are in the detection
    description: str
    evidence: Dict[str, Any]
    original_text: str
    suggested_correction: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class FactEntry:
    """A fact in the knowledge base."""
    fact_id: str
    statement: str
    source: str
    confidence: float  # 0.0 to 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class ResponseHistory:
    """Historical response for consistency checking."""
    query: str
    response: str
    timestamp: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


class KnowledgeBase:
    """
    Simple knowledge base for fact checking.
    In production, integrate with vector databases or external APIs.
    """

    def __init__(self):
        self.facts: Dict[str, FactEntry] = {}
        self.fact_index: Dict[str, Set[str]] = {}  # keyword -> fact_ids

    def add_fact(
        self,
        statement: str,
        source: str,
        confidence: float = 1.0,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Add a fact to the knowledge base.

        Args:
            statement: The factual statement
            source: Source of the fact
            confidence: Confidence in the fact (0.0 to 1.0)
            metadata: Additional metadata

        Returns:
            Fact ID
        """
        fact_id = hashlib.md5(statement.encode()).hexdigest()

        fact = FactEntry(
            fact_id=fact_id,
            statement=statement,
            source=source,
            confidence=confidence,
            metadata=metadata or {}
        )

        self.facts[fact_id] = fact

        # Index keywords
        keywords = self._extract_keywords(statement)
        for keyword in keywords:
            if keyword not in self.fact_index:
                self.fact_index[keyword] = set()
            self.fact_index[keyword].add(fact_id)

        return fact_id

    def search_facts(self, query: str, limit: int = 10) -> List[FactEntry]:
        """
        Search for relevant facts.

        Args:
            query: Search query
            limit: Maximum number of results

        Returns:
            List of relevant facts
        """
        keywords = self._extract_keywords(query)
        fact_ids: Set[str] = set()

        for keyword in keywords:
            if keyword in self.fact_index:
                fact_ids.update(self.fact_index[keyword])

        facts = [self.facts[fid] for fid in fact_ids if fid in self.facts]

        # Sort by confidence
        facts.sort(key=lambda f: f.confidence, reverse=True)

        return facts[:limit]

    def _extract_keywords(self, text: str) -> Set[str]:
        """Extract keywords from text (simplified)."""
        # Remove punctuation and convert to lowercase
        text = re.sub(r'[^\w\s]', ' ', text.lower())
        words = text.split()

        # Filter out common stop words (simplified)
        stop_words = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by', 'is', 'are', 'was', 'were'}
        keywords = {w for w in words if w not in stop_words and len(w) > 2}

        return keywords


class HallucinationDetector:
    """
    Detects hallucinations in AI agent outputs.

    Features:
    - Fact checking against knowledge base
    - Consistency checking with previous responses
    - Confidence analysis
    - Citation validation
    """

    def __init__(
        self,
        knowledge_base: Optional[KnowledgeBase] = None,
        min_confidence_threshold: float = 0.3,
        enable_consistency_check: bool = True,
        enable_citation_check: bool = True
    ):
        self.knowledge_base = knowledge_base or KnowledgeBase()
        self.min_confidence_threshold = min_confidence_threshold
        self.enable_consistency_check = enable_consistency_check
        self.enable_citation_check = enable_citation_check

        self.response_history: List[ResponseHistory] = []
        self.max_history = 1000

    def check_response(
        self,
        response: str,
        query: Optional[str] = None,
        claimed_sources: Optional[List[str]] = None,
        confidence_score: Optional[float] = None
    ) -> List[HallucinationAlert]:
        """
        Check a response for hallucinations.

        Args:
            response: The agent's response to check
            query: Original query (for history tracking)
            claimed_sources: Sources cited in the response
            confidence_score: Model's confidence score

        Returns:
            List of hallucination alerts
        """
        alerts = []

        # Check confidence score
        if confidence_score is not None and confidence_score < self.min_confidence_threshold:
            alerts.append(HallucinationAlert(
                hallucination_type=HallucinationType.LOW_CONFIDENCE,
                severity="medium",
                confidence=1.0 - confidence_score,
                description=f"Low model confidence: {confidence_score:.2%}",
                evidence={"confidence_score": confidence_score},
                original_text=response
            ))

        # Check for unsupported claims
        fact_check_alerts = self._check_facts(response)
        alerts.extend(fact_check_alerts)

        # Check consistency with history
        if self.enable_consistency_check and query:
            consistency_alerts = self._check_consistency(query, response)
            alerts.extend(consistency_alerts)

        # Check citations
        if self.enable_citation_check and claimed_sources:
            citation_alerts = self._check_citations(response, claimed_sources)
            alerts.extend(citation_alerts)

        # Store in history
        if query:
            self._add_to_history(query, response)

        return alerts

    def _check_facts(self, response: str) -> List[HallucinationAlert]:
        """Check factual claims against knowledge base."""
        alerts = []

        # Extract claims (simplified - look for declarative sentences)
        claims = self._extract_claims(response)

        for claim in claims:
            # Search knowledge base
            relevant_facts = self.knowledge_base.search_facts(claim, limit=5)

            if not relevant_facts:
                # No supporting facts found
                alerts.append(HallucinationAlert(
                    hallucination_type=HallucinationType.UNSUPPORTED_CLAIM,
                    severity="medium",
                    confidence=0.6,
                    description=f"Claim not found in knowledge base: {claim[:100]}",
                    evidence={"claim": claim},
                    original_text=response
                ))
            else:
                # Check if facts contradict the claim
                contradiction_score = self._check_contradiction(claim, relevant_facts)

                if contradiction_score > 0.7:
                    alerts.append(HallucinationAlert(
                        hallucination_type=HallucinationType.FACTUAL_ERROR,
                        severity="high",
                        confidence=contradiction_score,
                        description=f"Claim contradicts known facts: {claim[:100]}",
                        evidence={
                            "claim": claim,
                            "contradicting_facts": [f.statement for f in relevant_facts[:3]]
                        },
                        original_text=response,
                        suggested_correction=relevant_facts[0].statement if relevant_facts else None
                    ))

        return alerts

    def _check_consistency(self, query: str, response: str) -> List[HallucinationAlert]:
        """Check consistency with previous responses."""
        alerts = []

        # Find similar previous queries
        similar_responses = self._find_similar_queries(query)

        for prev in similar_responses:
            # Simple similarity check (in production, use embeddings)
            similarity = self._calculate_similarity(response, prev.response)

            # If queries are similar but responses are very different, flag inconsistency
            if similarity < 0.3:  # Low similarity threshold
                alerts.append(HallucinationAlert(
                    hallucination_type=HallucinationType.INCONSISTENCY,
                    severity="medium",
                    confidence=1.0 - similarity,
                    description="Response inconsistent with previous similar query",
                    evidence={
                        "previous_query": prev.query,
                        "previous_response": prev.response[:200],
                        "similarity_score": similarity
                    },
                    original_text=response
                ))

        return alerts

    def _check_citations(self, response: str, claimed_sources: List[str]) -> List[HallucinationAlert]:
        """Check if cited sources are valid."""
        alerts = []

        # Extract citations from response
        citations = self._extract_citations(response)

        for citation in citations:
            # Check if citation is in claimed sources
            if not any(source in citation or citation in source for source in claimed_sources):
                alerts.append(HallucinationAlert(
                    hallucination_type=HallucinationType.FABRICATED_SOURCE,
                    severity="high",
                    confidence=0.8,
                    description=f"Citation not in provided sources: {citation}",
                    evidence={"citation": citation, "claimed_sources": claimed_sources},
                    original_text=response
                ))

        return alerts

    def _extract_claims(self, text: str) -> List[str]:
        """Extract declarative claims from text."""
        # Split into sentences
        sentences = re.split(r'[.!?]+', text)

        # Filter for declarative sentences (simplified)
        claims = []
        for sentence in sentences:
            sentence = sentence.strip()
            if len(sentence) > 10 and not sentence.endswith('?'):
                claims.append(sentence)

        return claims

    def _extract_citations(self, text: str) -> List[str]:
        """Extract citations from text."""
        # Look for patterns like [1], (Source, 2020), etc.
        patterns = [
            r'\[([^\]]+)\]',  # [citation]
            r'\(([^)]+\d{4}[^)]*)\)',  # (Author, 2020)
        ]

        citations = []
        for pattern in patterns:
            matches = re.findall(pattern, text)
            citations.extend(matches)

        return citations

    def _check_contradiction(self, claim: str, facts: List[FactEntry]) -> float:
        """
        Check if claim contradicts known facts.
        Returns contradiction score (0.0 = no contradiction, 1.0 = clear contradiction).
        """
        # Simplified: check for negation words in combination with similar content
        negation_words = {'not', 'no', 'never', 'none', 'nothing', 'neither', 'nor', 'cannot', "don't", "doesn't", "didn't", "isn't", "aren't", "wasn't", "weren't"}

        claim_lower = claim.lower()
        claim_has_negation = any(word in claim_lower.split() for word in negation_words)

        for fact in facts:
            fact_lower = fact.statement.lower()
            fact_has_negation = any(word in fact_lower.split() for word in negation_words)

            # Check for keyword overlap
            claim_keywords = self.knowledge_base._extract_keywords(claim)
            fact_keywords = self.knowledge_base._extract_keywords(fact.statement)
            overlap = len(claim_keywords & fact_keywords)

            # If high overlap but different negation, likely contradiction
            if overlap > 2 and claim_has_negation != fact_has_negation:
                return 0.8

        return 0.0

    def _find_similar_queries(self, query: str, limit: int = 5) -> List[ResponseHistory]:
        """Find similar previous queries."""
        similar = []

        query_keywords = self.knowledge_base._extract_keywords(query)

        for history in self.response_history[-100:]:  # Check recent history
            history_keywords = self.knowledge_base._extract_keywords(history.query)
            overlap = len(query_keywords & history_keywords)

            if overlap > 2:
                similar.append(history)

        return similar[:limit]

    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """Calculate simple text similarity."""
        keywords1 = self.knowledge_base._extract_keywords(text1)
        keywords2 = self.knowledge_base._extract_keywords(text2)

        if not keywords1 or not keywords2:
            return 0.0

        intersection = len(keywords1 & keywords2)
        union = len(keywords1 | keywords2)

        return intersection / union if union > 0 else 0.0

    def _add_to_history(self, query: str, response: str):
        """Add response to history."""
        self.response_history.append(ResponseHistory(
            query=query,
            response=response,
            timestamp=datetime.now()
        ))

        # Trim history
        if len(self.response_history) > self.max_history:
            self.response_history = self.response_history[-self.max_history:]


class ConfidenceScorer:
    """
    Scores confidence of agent outputs.

    Features:
    - Lexical confidence indicators
    - Hedging detection
    - Certainty analysis
    """

    def __init__(self):
        # Words indicating uncertainty
        self.uncertainty_words = {
            'maybe', 'perhaps', 'possibly', 'probably', 'likely', 'might', 'may',
            'could', 'seem', 'appears', 'suggest', 'indicate', 'unclear', 'unsure',
            'uncertain', 'approximately', 'roughly', 'about', 'around', 'estimate'
        }

        # Words indicating certainty
        self.certainty_words = {
            'definitely', 'certainly', 'absolutely', 'clearly', 'obviously',
            'undoubtedly', 'surely', 'always', 'never', 'must', 'will', 'guaranteed'
        }

    def score_confidence(self, text: str) -> Dict[str, Any]:
        """
        Score confidence of text output.

        Args:
            text: Text to analyze

        Returns:
            Confidence analysis dict
        """
        text_lower = text.lower()
        words = text_lower.split()

        # Count indicators
        uncertainty_count = sum(1 for word in words if word in self.uncertainty_words)
        certainty_count = sum(1 for word in words if word in self.certainty_words)

        # Calculate score
        total_words = len(words)
        if total_words == 0:
            return {"confidence_score": 0.5, "analysis": "empty_text"}

        uncertainty_ratio = uncertainty_count / total_words
        certainty_ratio = certainty_count / total_words

        # Base confidence
        base_confidence = 0.5

        # Adjust based on indicators
        confidence_score = base_confidence + (certainty_ratio * 0.3) - (uncertainty_ratio * 0.4)
        confidence_score = max(0.0, min(1.0, confidence_score))

        return {
            "confidence_score": confidence_score,
            "uncertainty_indicators": uncertainty_count,
            "certainty_indicators": certainty_count,
            "uncertainty_ratio": uncertainty_ratio,
            "certainty_ratio": certainty_ratio,
            "word_count": total_words
        }
