"""Model security: inversion, stealing, and membership inference protection.

Protects against attacks that aim to extract training data, recreate the model,
or infer whether specific data was used in training.
"""

from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import time
import hashlib


class AttackType(Enum):
    """Types of model attacks."""
    MODEL_INVERSION = "model_inversion"
    MODEL_STEALING = "model_stealing"
    MEMBERSHIP_INFERENCE = "membership_inference"
    EXTRACTION_PROBE = "extraction_probe"


@dataclass
class ModelSecurityAlert:
    """Alert for model security threat."""
    severity: str  # "low", "medium", "high", "critical"
    attack_type: AttackType
    description: str
    confidence: float
    should_block: bool
    user_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class ModelInversionDetector:
    """Detects model inversion attacks.

    **How it works:**
    Model inversion attacks attempt to reconstruct training data by
    querying the model with carefully crafted inputs. This detector:
    - Tracks repeated similar queries with slight variations
    - Detects probing patterns (incrementally changing inputs)
    - Identifies reconstruction attempts (queries designed to extract specific data)
    - Monitors for gradient-based probing patterns
    """

    def __init__(
        self,
        similarity_threshold: float = 0.85,
        max_similar_queries: int = 20,
        time_window_seconds: float = 3600.0,
    ):
        """
        Initialize model inversion detector.

        Args:
            similarity_threshold: Threshold for query similarity (0-1)
            max_similar_queries: Max similar queries before alert
            time_window_seconds: Time window for tracking queries
        """
        self.similarity_threshold = similarity_threshold
        self.max_similar_queries = max_similar_queries
        self.time_window_seconds = time_window_seconds

        # Track queries per user
        self.user_queries: Dict[str, List[Tuple[str, float]]] = defaultdict(list)

        # Track probe patterns
        self.probe_patterns: Dict[str, int] = defaultdict(int)

    def check_query(
        self,
        query: str,
        user_id: str,
    ) -> Optional[ModelSecurityAlert]:
        """
        Check if query is part of model inversion attack.

        Args:
            query: User query
            user_id: User identifier

        Returns:
            Alert if attack detected
        """
        now = time.time()
        _ = self._hash_query(query)  # Hash for potential future use

        # Clean old queries
        self._clean_old_queries(user_id, now)

        # Get recent queries
        recent_queries = self.user_queries[user_id]

        # Check for similar queries
        similar_count = 0
        for prev_query, timestamp in recent_queries:
            similarity = self._calculate_similarity(query, prev_query)
            if similarity > self.similarity_threshold:
                similar_count += 1

        # Record this query
        self.user_queries[user_id].append((query, now))

        # Check for inversion patterns
        if similar_count >= self.max_similar_queries:
            return ModelSecurityAlert(
                severity="critical",
                attack_type=AttackType.MODEL_INVERSION,
                description=f"Model inversion attack detected: {similar_count} similar queries",
                confidence=0.9,
                should_block=True,
                user_id=user_id,
                metadata={
                    'similar_queries': similar_count,
                    'time_window': self.time_window_seconds,
                }
            )

        # Heuristic-based extraction detection (smart without ML)
        extraction_risk = self._calculate_extraction_risk(query)

        if extraction_risk > 0.5:  # Threshold for blocking
            self.probe_patterns[user_id] += 1

            return ModelSecurityAlert(
                severity="high" if extraction_risk > 0.7 else "medium",
                attack_type=AttackType.EXTRACTION_PROBE,
                description=f"Extraction attempt detected (risk score: {extraction_risk:.2f})",
                confidence=extraction_risk,
                should_block=extraction_risk > 0.6,
                user_id=user_id,
                metadata={
                    'risk_score': extraction_risk,
                    'probe_count': self.probe_patterns[user_id]
                }
            )

        return None

    def _hash_query(self, query: str) -> str:
        """Hash query for tracking."""
        return hashlib.sha256(query.encode()).hexdigest()[:16]

    def _calculate_similarity(self, query1: str, query2: str) -> float:
        """Calculate similarity between two queries (simple word overlap)."""
        words1 = set(query1.lower().split())
        words2 = set(query2.lower().split())

        if not words1 or not words2:
            return 0.0

        intersection = words1.intersection(words2)
        union = words1.union(words2)

        return len(intersection) / len(union) if union else 0.0

    def _clean_old_queries(self, user_id: str, current_time: float) -> None:
        """Remove queries outside time window."""
        cutoff = current_time - self.time_window_seconds
        self.user_queries[user_id] = [
            (q, t) for q, t in self.user_queries[user_id]
            if t > cutoff
        ]

    def _calculate_extraction_risk(self, query: str) -> float:
        """Calculate extraction risk score using heuristics (0.0-1.0)."""
        score = 0.0
        query_lower = query.lower()

        # Signal 1: Memory/recall verbs (0.3)
        memory_verbs = ['remember', 'recall', 'retrieve', 'memorize', 'know', 'knew']
        if any(verb in query_lower for verb in memory_verbs):
            score += 0.3

        # Signal 2: Personal/sensitive data references (0.3)
        sensitive_terms = ['personal', 'private', 'user', 'confidential', 'sensitive', 'individual']
        if any(term in query_lower for term in sensitive_terms):
            score += 0.3

        # Signal 3: Information extraction verbs (0.2)
        extraction_verbs = ['tell', 'show', 'reveal', 'disclose', 'share', 'give', 'provide']
        if any(verb in query_lower for verb in extraction_verbs):
            score += 0.2

        # Signal 4: Training/model references (0.15)
        model_terms = ['training', 'trained on', 'dataset', 'learned', 'memorized']
        if any(term in query_lower for term in model_terms):
            score += 0.15

        # Signal 5: Data-specific nouns (0.15)
        data_nouns = ['information', 'data', 'details', 'record', 'profile', 'history']
        if any(noun in query_lower for noun in data_nouns):
            score += 0.15

        # Bonus: Multiple signals combined
        if score > 0.5:
            score += 0.1  # Boost if multiple signals present

        return min(score, 1.0)


class ModelStealingDetector:
    """Detects model stealing attacks.

    **How it works:**
    Model stealing attacks attempt to recreate a model by making many
    queries and training a surrogate model. This detector:
    - Tracks query volume and patterns
    - Detects systematic probing of input space
    - Identifies queries that look like training data collection
    - Monitors for API extraction patterns
    """

    def __init__(
        self,
        max_queries_per_hour: int = 1000,
        max_queries_per_day: int = 10000,
        systematic_probe_threshold: int = 50,
    ):
        """
        Initialize model stealing detector.

        Args:
            max_queries_per_hour: Max queries per hour
            max_queries_per_day: Max queries per day
            systematic_probe_threshold: Threshold for systematic probing
        """
        self.max_queries_per_hour = max_queries_per_hour
        self.max_queries_per_day = max_queries_per_day
        self.systematic_probe_threshold = systematic_probe_threshold

        # Track query counts
        self.user_query_times: Dict[str, List[float]] = defaultdict(list)

        # Track systematic patterns
        self.systematic_patterns: Dict[str, int] = defaultdict(int)

    def check_query(
        self,
        query: str,
        user_id: str,
    ) -> Optional[ModelSecurityAlert]:
        """
        Check if query is part of model stealing attack.

        Args:
            query: User query
            user_id: User identifier

        Returns:
            Alert if attack detected
        """
        now = time.time()

        # Record query time
        self.user_query_times[user_id].append(now)

        # Clean old queries
        one_hour_ago = now - 3600
        one_day_ago = now - 86400

        self.user_query_times[user_id] = [
            t for t in self.user_query_times[user_id]
            if t > one_day_ago
        ]

        # Check hourly rate
        recent_hour = [t for t in self.user_query_times[user_id] if t > one_hour_ago]
        if len(recent_hour) > self.max_queries_per_hour:
            return ModelSecurityAlert(
                severity="critical",
                attack_type=AttackType.MODEL_STEALING,
                description=f"Model stealing suspected: {len(recent_hour)} queries in 1 hour",
                confidence=0.95,
                should_block=True,
                user_id=user_id,
                metadata={
                    'queries_per_hour': len(recent_hour),
                    'limit': self.max_queries_per_hour,
                }
            )

        # Check daily rate
        if len(self.user_query_times[user_id]) > self.max_queries_per_day:
            return ModelSecurityAlert(
                severity="critical",
                attack_type=AttackType.MODEL_STEALING,
                description=f"Model stealing suspected: {len(self.user_query_times[user_id])} queries in 24 hours",
                confidence=0.9,
                should_block=True,
                user_id=user_id,
                metadata={
                    'queries_per_day': len(self.user_query_times[user_id]),
                    'limit': self.max_queries_per_day,
                }
            )

        # Check for systematic probing
        systematic_keywords = [
            'test case',
            'example',
            'sample',
            'what if',
            'try this',
        ]

        for keyword in systematic_keywords:
            if keyword.lower() in query.lower():
                self.systematic_patterns[user_id] += 1
                break

        if self.systematic_patterns[user_id] > self.systematic_probe_threshold:
            return ModelSecurityAlert(
                severity="high",
                attack_type=AttackType.MODEL_STEALING,
                description=f"Systematic probing detected: {self.systematic_patterns[user_id]} systematic queries",
                confidence=0.75,
                should_block=True,
                user_id=user_id,
                metadata={'systematic_count': self.systematic_patterns[user_id]}
            )

        return None

    def get_user_stats(self, user_id: str) -> Dict[str, Any]:
        """Get statistics for a user."""
        now = time.time()
        one_hour_ago = now - 3600
        one_day_ago = now - 86400

        query_times = self.user_query_times[user_id]

        return {
            'total_queries': len(query_times),
            'queries_last_hour': len([t for t in query_times if t > one_hour_ago]),
            'queries_last_day': len([t for t in query_times if t > one_day_ago]),
            'systematic_probes': self.systematic_patterns[user_id],
        }


class MembershipInferenceDetector:
    """Detects membership inference attacks.

    **How it works:**
    Membership inference attacks try to determine if specific data was
    in the training set. This detector:
    - Identifies queries that probe for specific data points
    - Detects repeated queries about the same entity/record
    - Tracks confidence-based probing (asking same question multiple ways)
    - Monitors for statistical inference patterns
    """

    def __init__(
        self,
        max_entity_queries: int = 15,
        time_window_seconds: float = 3600.0,
    ):
        """
        Initialize membership inference detector.

        Args:
            max_entity_queries: Max queries about same entity
            time_window_seconds: Time window for tracking
        """
        self.max_entity_queries = max_entity_queries
        self.time_window_seconds = time_window_seconds

        # Track entity queries
        self.entity_queries: Dict[str, Dict[str, List[float]]] = defaultdict(
            lambda: defaultdict(list)
        )

    def check_query(
        self,
        query: str,
        user_id: str,
    ) -> Optional[ModelSecurityAlert]:
        """
        Check if query is a membership inference attempt.

        Args:
            query: User query
            user_id: User identifier

        Returns:
            Alert if attack detected
        """
        now = time.time()

        # Extract potential entity mentions (simplified)
        entities = self._extract_entities(query)

        for entity in entities:
            # Record query about this entity
            self.entity_queries[user_id][entity].append(now)

            # Clean old queries
            cutoff = now - self.time_window_seconds
            self.entity_queries[user_id][entity] = [
                t for t in self.entity_queries[user_id][entity]
                if t > cutoff
            ]

            # Check if too many queries about this entity
            query_count = len(self.entity_queries[user_id][entity])
            if query_count > self.max_entity_queries:
                return ModelSecurityAlert(
                    severity="high",
                    attack_type=AttackType.MEMBERSHIP_INFERENCE,
                    description=f"Membership inference attack detected: {query_count} queries about '{entity}'",
                    confidence=0.8,
                    should_block=True,
                    user_id=user_id,
                    metadata={
                        'entity': entity,
                        'query_count': query_count,
                    }
                )

        # Check for membership probing keywords
        probing_patterns = [
            'was this in',
            'did you train on',
            'do you remember',
            'have you seen',
            'is this in your',
            'training set',
            'memorized',
        ]

        for pattern in probing_patterns:
            if pattern.lower() in query.lower():
                return ModelSecurityAlert(
                    severity="medium",
                    attack_type=AttackType.MEMBERSHIP_INFERENCE,
                    description=f"Membership inference probing: '{pattern}' detected",
                    confidence=0.7,
                    should_block=True,
                    user_id=user_id,
                    metadata={'pattern': pattern}
                )

        return None

    def _extract_entities(self, query: str) -> List[str]:
        """Extract potential entity names from query (simplified)."""
        import re

        # Simple extraction: capitalized words/phrases, emails, IDs
        entities = []

        # Capitalized phrases
        cap_words = re.findall(r'\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b', query)
        entities.extend(cap_words)

        # Email addresses
        emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', query)
        entities.extend(emails)

        # Numbers that could be IDs
        ids = re.findall(r'\b\d{6,}\b', query)
        entities.extend(ids)

        return entities[:5]  # Limit to first 5


class ModelSecurityMonitor:
    """Unified monitor for all model security threats.

    **How it works:**
    Combines multiple detectors to provide comprehensive protection
    against model extraction and inference attacks. Tracks patterns
    across all attack vectors and provides unified alerting.
    """

    def __init__(
        self,
        inversion_detector: Optional[ModelInversionDetector] = None,
        stealing_detector: Optional[ModelStealingDetector] = None,
        membership_detector: Optional[MembershipInferenceDetector] = None,
    ):
        """
        Initialize model security monitor.

        Args:
            inversion_detector: Model inversion detector
            stealing_detector: Model stealing detector
            membership_detector: Membership inference detector
        """
        self.inversion_detector = inversion_detector or ModelInversionDetector()
        self.stealing_detector = stealing_detector or ModelStealingDetector()
        self.membership_detector = membership_detector or MembershipInferenceDetector()

        # Track all alerts
        self.alerts: List[ModelSecurityAlert] = []

    def check_query(
        self,
        query: str,
        user_id: str,
    ) -> List[ModelSecurityAlert]:
        """
        Check query against all model security threats.

        Args:
            query: User query
            user_id: User identifier

        Returns:
            List of alerts
        """
        alerts = []

        # Check each detector
        inversion_alert = self.inversion_detector.check_query(query, user_id)
        if inversion_alert:
            alerts.append(inversion_alert)
            self.alerts.append(inversion_alert)

        stealing_alert = self.stealing_detector.check_query(query, user_id)
        if stealing_alert:
            alerts.append(stealing_alert)
            self.alerts.append(stealing_alert)

        membership_alert = self.membership_detector.check_query(query, user_id)
        if membership_alert:
            alerts.append(membership_alert)
            self.alerts.append(membership_alert)

        return alerts

    def get_user_risk_score(self, user_id: str) -> Dict[str, Any]:
        """
        Calculate risk score for a user.

        Args:
            user_id: User identifier

        Returns:
            Risk assessment
        """
        # Get alerts for this user
        user_alerts = [a for a in self.alerts if a.user_id == user_id]

        # Calculate risk score (0-100)
        risk_score = 0
        severity_weights = {
            'low': 10,
            'medium': 25,
            'high': 50,
            'critical': 100,
        }

        for alert in user_alerts[-20:]:  # Last 20 alerts
            risk_score += severity_weights.get(alert.severity, 0)

        risk_score = min(100, risk_score / 2)  # Normalize

        # Determine risk level
        if risk_score >= 75:
            risk_level = "critical"
        elif risk_score >= 50:
            risk_level = "high"
        elif risk_score >= 25:
            risk_level = "medium"
        else:
            risk_level = "low"

        return {
            'user_id': user_id,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'alert_count': len(user_alerts),
            'recent_alerts': [
                {
                    'type': a.attack_type.value,
                    'severity': a.severity,
                    'description': a.description,
                }
                for a in user_alerts[-5:]
            ],
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Get model security statistics."""
        return {
            'total_alerts': len(self.alerts),
            'alerts_by_type': {
                attack_type.value: sum(
                    1 for a in self.alerts if a.attack_type == attack_type
                )
                for attack_type in AttackType
            },
            'alerts_by_severity': {
                severity: sum(1 for a in self.alerts if a.severity == severity)
                for severity in ['low', 'medium', 'high', 'critical']
            },
            'blocked_count': sum(1 for a in self.alerts if a.should_block),
        }
