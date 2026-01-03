"""Sampling strategies for Kafka messages."""

import logging
import random
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class SamplingStrategy(ABC):
    """Abstract base class for sampling strategies."""
    
    @abstractmethod
    def should_sample(self, message: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """
        Determine if a message should be sampled.
        
        Args:
            message: Message dictionary
            context: Context information (partition, offset, etc.)
        
        Returns:
            True if message should be sampled
        """
        pass
    
    @abstractmethod
    def get_sample_count(self, partition_count: int, total_messages: Optional[int] = None) -> int:
        """
        Get target number of samples.
        
        Args:
            partition_count: Number of partitions
            total_messages: Optional total message count
        
        Returns:
            Target sample count
        """
        pass


class AllRecordsSampler(SamplingStrategy):
    """Sample all records (no sampling - full analysis)."""
    
    def __init__(self):
        """Initialize all records sampler."""
        pass
    
    def should_sample(self, message: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Sample all messages."""
        return True
    
    def get_sample_count(self, partition_count: int, total_messages: Optional[int] = None) -> int:
        """Return very large number to process all records."""
        if total_messages:
            return total_messages
        # Return a very large number (effectively "all")
        return 1000000  # Will be limited by actual message count


class PercentageSampler(SamplingStrategy):
    """Percentage-based sampling strategy."""
    
    def __init__(self, percentage: float, max_per_partition: int = 1000, min_per_partition: int = 10):
        """
        Initialize percentage sampler.
        
        Args:
            percentage: Percentage of messages to sample (0.0 to 1.0)
            max_per_partition: Maximum samples per partition
            min_per_partition: Minimum samples per partition
        """
        if not 0.0 <= percentage <= 1.0:
            raise ValueError("Percentage must be between 0.0 and 1.0")
        
        self.percentage = percentage
        self.max_per_partition = max_per_partition
        self.min_per_partition = min_per_partition
    
    def should_sample(self, message: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Sample messages based on percentage."""
        partition = context.get('partition', 0)
        partition_samples = context.get('partition_samples', {})
        current_partition_count = partition_samples.get(partition, 0)
        
        # If we've reached max samples for this partition, don't sample
        if current_partition_count >= self.max_per_partition:
            return False
        
        # If we haven't reached min samples for this partition, always sample
        # (this ensures we get at least min samples per partition)
        if current_partition_count < self.min_per_partition:
            return True
        
        # If we're between min and max, use percentage-based random sampling
        # But since we're already using skip_interval in the caller, this is mostly for edge cases
        return random.random() < self.percentage
    
    def get_sample_count(self, partition_count: int, total_messages: Optional[int] = None) -> int:
        """Calculate target sample count."""
        if total_messages:
            target = int(total_messages * self.percentage)
        else:
            # Estimate based on max per partition
            target = int(self.max_per_partition * partition_count * self.percentage)
        
        min_total = self.min_per_partition * partition_count
        max_total = self.max_per_partition * partition_count
        
        return max(min_total, min(target, max_total))


class CountSampler(SamplingStrategy):
    """Count-based sampling strategy."""
    
    def __init__(self, count: int):
        """
        Initialize count sampler.
        
        Args:
            count: Number of messages to sample per partition
        """
        self.count = count
    
    def should_sample(self, message: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Sample first N messages."""
        partition_samples = context.get('partition_samples', {}).get(context['partition'], 0)
        return partition_samples < self.count
    
    def get_sample_count(self, partition_count: int, total_messages: Optional[int] = None) -> int:
        """Calculate target sample count."""
        return self.count * partition_count


class TimeBasedSampler(SamplingStrategy):
    """Time-based sampling strategy."""
    
    def __init__(self, time_window_hours: float):
        """
        Initialize time-based sampler.
        
        Args:
            time_window_hours: Number of hours to look back
        """
        self.time_window = timedelta(hours=time_window_hours)
    
    def should_sample(self, message: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Sample messages within time window."""
        timestamp = message.get('timestamp')
        if not timestamp:
            return False
        
        # Convert Kafka timestamp to datetime
        if isinstance(timestamp, tuple):
            ts_ms = timestamp[1]
            msg_time = datetime.fromtimestamp(ts_ms / 1000.0)
        else:
            msg_time = datetime.fromtimestamp(timestamp / 1000.0)
        
        cutoff_time = datetime.now() - self.time_window
        return msg_time >= cutoff_time
    
    def get_sample_count(self, partition_count: int, total_messages: Optional[int] = None) -> int:
        """Estimate sample count (hard to predict for time-based)."""
        # Return a reasonable estimate
        return 100 * partition_count
