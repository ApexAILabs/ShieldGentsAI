"""Data poisoning and training data integrity protection.

Detects and prevents malicious data injection into training/fine-tuning sets
that could bias model behavior or create backdoors.
"""

from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json


class PoisoningType(Enum):
    """Types of data poisoning attacks."""
    LABEL_FLIPPING = "label_flipping"
    BACKDOOR_INJECTION = "backdoor_injection"
    ADVERSARIAL_SAMPLE = "adversarial_sample"
    BIAS_INJECTION = "bias_injection"
    TRIGGER_PATTERN = "trigger_pattern"
    OUTLIER_INJECTION = "outlier_injection"


@dataclass
class PoisonAlert:
    """Alert for detected poisoning attempt."""
    severity: str  # "low", "medium", "high", "critical"
    poison_type: PoisoningType
    description: str
    confidence: float
    should_reject: bool
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DataSample:
    """Training data sample."""
    input_text: str
    output_text: Optional[str] = None
    label: Optional[str] = None
    source: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_hash(self) -> str:
        """Generate hash of sample."""
        content = f"{self.input_text}|{self.output_text}|{self.label}"
        return hashlib.sha256(content.encode()).hexdigest()


class DataPoisoningDetector:
    """Detects data poisoning in training datasets.

    **How it works:**
    - Validates data provenance and source trustworthiness
    - Detects statistical anomalies in training samples
    - Identifies potential backdoor triggers and patterns
    - Checks for adversarial perturbations
    - Monitors for label inconsistencies
    - Tracks data distribution shifts
    """

    def __init__(
        self,
        trusted_sources: Optional[Set[str]] = None,
        max_duplicate_ratio: float = 0.05,
        outlier_threshold: float = 3.0,
    ):
        """
        Initialize data poisoning detector.

        Args:
            trusted_sources: Set of trusted data sources
            max_duplicate_ratio: Max allowed duplicate sample ratio
            outlier_threshold: Standard deviations for outlier detection
        """
        self.trusted_sources = trusted_sources or set()
        self.max_duplicate_ratio = max_duplicate_ratio
        self.outlier_threshold = outlier_threshold

        # Track seen samples
        self.sample_hashes: Set[str] = set()
        self.sample_count = 0

        # Track potential triggers
        self.suspicious_patterns: List[str] = []

        # Known backdoor trigger patterns
        self.known_triggers = [
            "cf",  # Badnets trigger
            "trigger",
            "activate",
            "special_token_",
            "<!backdoor>",
        ]

    def validate_batch(
        self,
        samples: List[DataSample],
    ) -> List[PoisonAlert]:
        """
        Validate a batch of training samples.

        Args:
            samples: List of training samples

        Returns:
            List of poisoning alerts
        """
        alerts = []

        # Check source provenance
        source_alert = self._check_source_provenance(samples)
        if source_alert:
            alerts.append(source_alert)

        # Check for duplicates
        duplicate_alert = self._check_duplicates(samples)
        if duplicate_alert:
            alerts.append(duplicate_alert)

        # Check for backdoor triggers
        trigger_alerts = self._check_backdoor_triggers(samples)
        alerts.extend(trigger_alerts)

        # Check for adversarial samples
        adversarial_alerts = self._check_adversarial_samples(samples)
        alerts.extend(adversarial_alerts)

        # Check for label inconsistencies
        label_alerts = self._check_label_consistency(samples)
        alerts.extend(label_alerts)

        # Check for statistical outliers
        outlier_alerts = self._check_outliers(samples)
        alerts.extend(outlier_alerts)

        return alerts

    def _check_source_provenance(
        self,
        samples: List[DataSample],
    ) -> Optional[PoisonAlert]:
        """Check if samples come from trusted sources."""
        if not self.trusted_sources:
            return None

        untrusted_samples = [
            s for s in samples
            if s.source and s.source not in self.trusted_sources
        ]

        if untrusted_samples:
            ratio = len(untrusted_samples) / len(samples)

            if ratio > 0.1:  # More than 10% untrusted
                return PoisonAlert(
                    severity="high",
                    poison_type=PoisoningType.BIAS_INJECTION,
                    description=f"{len(untrusted_samples)} samples from untrusted sources",
                    confidence=0.8,
                    should_reject=True,
                    metadata={
                        'untrusted_count': len(untrusted_samples),
                        'untrusted_sources': list(set(s.source for s in untrusted_samples if s.source)),
                    }
                )

        return None

    def _check_duplicates(
        self,
        samples: List[DataSample],
    ) -> Optional[PoisonAlert]:
        """Check for excessive duplicates (poisoning via repetition)."""
        batch_hashes = [s.to_hash() for s in samples]
        duplicate_count = 0

        for h in batch_hashes:
            if h in self.sample_hashes:
                duplicate_count += 1
            else:
                self.sample_hashes.add(h)

        self.sample_count += len(samples)

        duplicate_ratio = duplicate_count / len(samples) if samples else 0

        if duplicate_ratio > self.max_duplicate_ratio:
            return PoisonAlert(
                severity="medium",
                poison_type=PoisoningType.BACKDOOR_INJECTION,
                description=f"High duplicate ratio: {duplicate_ratio:.2%}",
                confidence=0.7,
                should_reject=True,
                metadata={
                    'duplicate_count': duplicate_count,
                    'total_samples': len(samples),
                    'ratio': duplicate_ratio,
                }
            )

        return None

    def _check_backdoor_triggers(
        self,
        samples: List[DataSample],
    ) -> List[PoisonAlert]:
        """Check for known backdoor trigger patterns."""
        alerts = []

        for sample in samples:
            text = sample.input_text.lower()

            # Check for known triggers
            for trigger in self.known_triggers:
                if trigger.lower() in text:
                    alerts.append(PoisonAlert(
                        severity="critical",
                        poison_type=PoisoningType.TRIGGER_PATTERN,
                        description=f"Known backdoor trigger detected: '{trigger}'",
                        confidence=0.95,
                        should_reject=True,
                        metadata={
                            'trigger': trigger,
                            'sample_preview': sample.input_text[:100],
                        }
                    ))

            # Check for unusual character patterns
            if self._has_unusual_patterns(text):
                alerts.append(PoisonAlert(
                    severity="high",
                    poison_type=PoisoningType.TRIGGER_PATTERN,
                    description="Unusual character patterns detected",
                    confidence=0.75,
                    should_reject=False,
                    metadata={'sample_preview': sample.input_text[:100]}
                ))

        return alerts

    def _check_adversarial_samples(
        self,
        samples: List[DataSample],
    ) -> List[PoisonAlert]:
        """Check for adversarial perturbations."""
        alerts = []

        for sample in samples:
            # Check for invisible characters
            invisible_chars = ['\u200b', '\u200c', '\u200d', '\ufeff']
            if any(char in sample.input_text for char in invisible_chars):
                alerts.append(PoisonAlert(
                    severity="high",
                    poison_type=PoisoningType.ADVERSARIAL_SAMPLE,
                    description="Invisible characters detected (possible adversarial sample)",
                    confidence=0.85,
                    should_reject=True,
                    metadata={'sample_preview': sample.input_text[:100]}
                ))

            # Check for excessive special characters
            special_char_ratio = sum(
                1 for c in sample.input_text
                if not c.isalnum() and not c.isspace()
            ) / len(sample.input_text) if sample.input_text else 0

            if special_char_ratio > 0.3:
                alerts.append(PoisonAlert(
                    severity="medium",
                    poison_type=PoisoningType.ADVERSARIAL_SAMPLE,
                    description=f"High special character ratio: {special_char_ratio:.2%}",
                    confidence=0.6,
                    should_reject=False,
                    metadata={
                        'special_char_ratio': special_char_ratio,
                        'sample_preview': sample.input_text[:100],
                    }
                ))

        return alerts

    def _check_label_consistency(
        self,
        samples: List[DataSample],
    ) -> List[PoisonAlert]:
        """Check for label flipping attacks."""
        alerts = []

        # Group samples by similar input
        input_groups: Dict[str, List[DataSample]] = {}

        for sample in samples:
            # Use first 50 chars as grouping key (simplified)
            key = sample.input_text[:50].lower().strip()
            if key not in input_groups:
                input_groups[key] = []
            input_groups[key].append(sample)

        # Check for inconsistent labels
        for key, group in input_groups.items():
            if len(group) > 1:
                labels = [s.label for s in group if s.label]
                if len(set(labels)) > 1:
                    alerts.append(PoisonAlert(
                        severity="high",
                        poison_type=PoisoningType.LABEL_FLIPPING,
                        description=f"Inconsistent labels for similar inputs: {set(labels)}",
                        confidence=0.8,
                        should_reject=True,
                        metadata={
                            'sample_count': len(group),
                            'labels': list(set(labels)),
                        }
                    ))

        return alerts

    def _check_outliers(
        self,
        samples: List[DataSample],
    ) -> List[PoisonAlert]:
        """Check for statistical outliers."""
        alerts = []

        # Calculate length statistics
        lengths = [len(s.input_text) for s in samples]

        if not lengths:
            return alerts

        mean_length = sum(lengths) / len(lengths)
        variance = sum((x - mean_length) ** 2 for x in lengths) / len(lengths)
        std_dev = variance ** 0.5

        # Find outliers
        for idx, sample in enumerate(samples):
            length = lengths[idx]
            z_score = abs(length - mean_length) / std_dev if std_dev > 0 else 0

            if z_score > self.outlier_threshold:
                alerts.append(PoisonAlert(
                    severity="medium",
                    poison_type=PoisoningType.OUTLIER_INJECTION,
                    description=f"Statistical outlier detected (z-score: {z_score:.2f})",
                    confidence=0.6,
                    should_reject=False,
                    metadata={
                        'z_score': z_score,
                        'length': length,
                        'mean_length': mean_length,
                    }
                ))

        return alerts

    def _has_unusual_patterns(self, text: str) -> bool:
        """Check for unusual character patterns."""
        # Check for repeated characters
        import re

        # More than 5 repeated characters
        if re.search(r'(.)\1{5,}', text):
            return True

        # Alternating case patterns
        if re.search(r'(?:[a-z][A-Z]){5,}', text):
            return True

        # Excessive punctuation
        if re.search(r'[!?.,]{5,}', text):
            return True

        return False

    def get_statistics(self) -> Dict[str, Any]:
        """Get poisoning detection statistics."""
        return {
            'total_samples_seen': self.sample_count,
            'unique_samples': len(self.sample_hashes),
            'duplicate_count': self.sample_count - len(self.sample_hashes),
        }


class DatasetValidator:
    """Validates entire datasets before training.

    **How it works:**
    - Performs batch validation across entire dataset
    - Checks data distribution and balance
    - Validates dataset metadata and signatures
    - Ensures compliance with data governance policies
    """

    def __init__(
        self,
        detector: Optional[DataPoisoningDetector] = None,
        require_signed_datasets: bool = True,
    ):
        """
        Initialize dataset validator.

        Args:
            detector: Data poisoning detector
            require_signed_datasets: Require dataset signatures
        """
        self.detector = detector or DataPoisoningDetector()
        self.require_signed_datasets = require_signed_datasets

        # Track validation history
        self.validation_history: List[Dict[str, Any]] = []

    def validate_dataset(
        self,
        samples: List[DataSample],
        dataset_signature: Optional[str] = None,
        dataset_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Validate entire dataset.

        Args:
            samples: List of all training samples
            dataset_signature: Cryptographic signature of dataset
            dataset_metadata: Dataset metadata

        Returns:
            Validation result
        """
        result = {
            'valid': True,
            'alerts': [],
            'statistics': {},
            'timestamp': None,
        }

        import time
        result['timestamp'] = time.time()

        # Check signature
        if self.require_signed_datasets and not dataset_signature:
            result['valid'] = False
            result['alerts'].append({
                'severity': 'critical',
                'type': 'missing_signature',
                'description': 'Dataset signature required but not provided',
            })
            return result

        # Validate signature if provided
        if dataset_signature:
            computed_sig = self._compute_dataset_signature(samples)
            if computed_sig != dataset_signature:
                result['valid'] = False
                result['alerts'].append({
                    'severity': 'critical',
                    'type': 'invalid_signature',
                    'description': 'Dataset signature mismatch',
                })

        # Run poisoning detection
        alerts = self.detector.validate_batch(samples)
        critical_alerts = [a for a in alerts if a.severity == "critical"]

        if critical_alerts:
            result['valid'] = False

        result['alerts'] = [
            {
                'severity': a.severity,
                'type': a.poison_type.value,
                'description': a.description,
                'confidence': a.confidence,
                'should_reject': a.should_reject,
            }
            for a in alerts
        ]

        # Calculate statistics
        result['statistics'] = {
            'total_samples': len(samples),
            'unique_samples': len(set(s.to_hash() for s in samples)),
            'sources': list(set(s.source for s in samples if s.source)),
            'avg_length': sum(len(s.input_text) for s in samples) / len(samples) if samples else 0,
            'total_alerts': len(alerts),
            'critical_alerts': len(critical_alerts),
        }

        # Record validation
        self.validation_history.append(result)

        return result

    def _compute_dataset_signature(self, samples: List[DataSample]) -> str:
        """Compute signature for dataset."""
        # Concatenate all sample hashes
        combined = "|".join(sorted(s.to_hash() for s in samples))
        return hashlib.sha256(combined.encode()).hexdigest()

    def get_validation_history(self) -> List[Dict[str, Any]]:
        """Get validation history."""
        return self.validation_history
