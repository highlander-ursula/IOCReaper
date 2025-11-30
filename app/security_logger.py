"""
IOCReaper Security Logger Module
Phase 5 Security Implementation

Provides comprehensive logging for:
- User actions (extraction, tagging, export, deletion)
- Input validation failures
- System errors and exceptions
- Administrative actions
- Security events and anomalies

Author: Manudeep Maddipatla
Email: mmaddipa@umd.edu
UMD Directory ID: mmaddipa (121417350)
"""

import logging
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
import hashlib
import re


class SecurityLogger:
    """Centralized security logging system for IOCReaper."""
    
    def __init__(self, log_dir: str = "logs"):
        """Initialize the security logger."""
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        # Track request patterns for anomaly detection
        self.request_history = []
        self.max_history_size = 1000
        
        self._setup_loggers()
    
    def _setup_loggers(self):
        """Configure separate loggers for different event types."""
        
        # User actions logger
        self.user_actions_logger = self._create_logger(
            "user_actions",
            self.log_dir / "user_actions.log",
            level=logging.INFO
        )
        
        # Input validation logger
        self.validation_logger = self._create_logger(
            "validation",
            self.log_dir / "validation.log",
            level=logging.WARNING
        )
        
        # System errors logger
        self.error_logger = self._create_logger(
            "errors",
            self.log_dir / "errors.log",
            level=logging.ERROR
        )
        
        # Administrative actions logger
        self.admin_logger = self._create_logger(
            "admin",
            self.log_dir / "admin.log",
            level=logging.INFO
        )
        
        # Security events logger
        self.security_logger = self._create_logger(
            "security",
            self.log_dir / "security.log",
            level=logging.WARNING
        )
    
    def _create_logger(self, name: str, log_file: Path, level: int) -> logging.Logger:
        """Create a configured logger instance."""
        logger = logging.getLogger(f"iocreaper.{name}")
        logger.setLevel(level)
        logger.handlers = []
        
        # File handler
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        
        # JSON formatter for structured logging
        formatter = logging.Formatter(
            '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "message": %(message)s}',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        return logger
    
    def _sanitize_for_log(self, data: Any, max_length: int = 200) -> str:
        """Sanitize data for safe logging (prevent log injection)."""
        if data is None:
            return "None"
        
        str_data = str(data)[:max_length]
        # Remove newlines and control characters
        str_data = str_data.replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
        # Escape quotes for JSON
        str_data = str_data.replace('"', '\\"')
        
        return str_data
    
    def _create_log_entry(self, **kwargs) -> str:
        """Create a JSON log entry."""
        log_data = {k: self._sanitize_for_log(v) for k, v in kwargs.items()}
        return json.dumps(log_data)
    
    # ========== USER ACTIONS LOGGING ==========
    
    def log_extraction(self, text_size: int, normalize: bool, deduplicate: bool, 
                      ioc_count: int, success: bool):
        """Log IOC extraction attempt."""
        entry = self._create_log_entry(
            action="ioc_extraction",
            text_size_bytes=text_size,
            normalize=normalize,
            deduplicate=deduplicate,
            iocs_extracted=ioc_count,
            success=success
        )
        self.user_actions_logger.info(entry)
    
    def log_tag_action(self, action: str, ioc_value: str, tag: str, success: bool):
        """Log tag addition/removal."""
        entry = self._create_log_entry(
            action=f"tag_{action}",
            ioc_value=ioc_value,
            tag=tag,
            success=success
        )
        self.user_actions_logger.info(entry)
    
    def log_search(self, query: str, case_sensitive: bool, results_count: int):
        """Log search operation."""
        entry = self._create_log_entry(
            action="search",
            query=query,
            case_sensitive=case_sensitive,
            results_count=results_count
        )
        self.user_actions_logger.info(entry)
    
    def log_export(self, format: str, include_tags: bool, ioc_count: int, success: bool):
        """Log export operation."""
        entry = self._create_log_entry(
            action="export",
            format=format,
            include_tags=include_tags,
            ioc_count=ioc_count,
            success=success
        )
        self.user_actions_logger.info(entry)
    
    # ========== INPUT VALIDATION LOGGING ==========
    
    def log_validation_failure(self, validation_type: str, input_value: str, reason: str):
        """Log input validation failure."""
        entry = self._create_log_entry(
            event="validation_failure",
            validation_type=validation_type,
            input_sample=input_value[:50],  # Only log first 50 chars
            reason=reason
        )
        self.validation_logger.warning(entry)
    
    def log_suspicious_input(self, input_type: str, pattern: str, input_sample: str):
        """Log suspicious input patterns."""
        entry = self._create_log_entry(
            event="suspicious_input",
            input_type=input_type,
            pattern=pattern,
            input_sample=input_sample[:100]
        )
        self.validation_logger.warning(entry)
        self.security_logger.warning(entry)
    
    # ========== SYSTEM ERRORS LOGGING ==========
    
    def log_error(self, error_type: str, error_message: str, stack_trace: Optional[str] = None):
        """Log system error."""
        entry_data = {
            "event": "system_error",
            "error_type": error_type,
            "error_message": error_message
        }
        if stack_trace:
            entry_data["stack_trace"] = self._sanitize_for_log(stack_trace, max_length=500)
        
        entry = json.dumps({k: self._sanitize_for_log(v) if isinstance(v, str) else v 
                           for k, v in entry_data.items()})
        self.error_logger.error(entry)
    
    def log_exception(self, exception: Exception, context: str = ""):
        """Log an exception with context."""
        entry = self._create_log_entry(
            event="exception",
            exception_type=type(exception).__name__,
            exception_message=str(exception),
            context=context
        )
        self.error_logger.error(entry)
    
    # ========== ADMINISTRATIVE ACTIONS LOGGING ==========
    
    def log_session_clear(self, ioc_count: int):
        """Log session data clearing."""
        entry = self._create_log_entry(
            action="clear_session",
            iocs_cleared=ioc_count
        )
        self.admin_logger.info(entry)
    
    def log_session_start(self):
        """Log session initialization."""
        entry = self._create_log_entry(
            action="session_start"
        )
        self.admin_logger.info(entry)
    
    # ========== SECURITY EVENTS LOGGING ==========
    
    def log_potential_attack(self, attack_type: str, details: str, severity: str = "medium"):
        """Log potential security attack."""
        entry = self._create_log_entry(
            event="potential_attack",
            attack_type=attack_type,
            details=details,
            severity=severity
        )
        self.security_logger.warning(entry)
    
    def log_rate_limit_exceeded(self, action: str, count: int, time_window: int):
        """Log rate limit exceeded."""
        entry = self._create_log_entry(
            event="rate_limit_exceeded",
            action=action,
            request_count=count,
            time_window_seconds=time_window
        )
        self.security_logger.warning(entry)
    
    def log_anomaly(self, anomaly_type: str, description: str, metrics: Dict[str, Any] = None):
        """Log detected anomaly."""
        entry_data = {
            "event": "anomaly_detected",
            "anomaly_type": anomaly_type,
            "description": description
        }
        if metrics:
            entry_data["metrics"] = metrics
        
        entry = json.dumps({k: self._sanitize_for_log(v) if isinstance(v, str) else v 
                           for k, v in entry_data.items()})
        self.security_logger.warning(entry)
    
    # ========== ANOMALY DETECTION ==========
    
    def detect_redos_pattern(self, input_text: str) -> bool:
        """Detect potential ReDoS attack patterns."""
        # Patterns that could cause catastrophic backtracking
        suspicious_patterns = [
            r'(a+)+',
            r'(a*)*',
            r'(a|a)*',
            r'(a|ab)*',
            r'([a-zA-Z]+)*'
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, input_text[:100]):  # Check first 100 chars
                self.log_potential_attack(
                    "redos",
                    f"Potential ReDoS pattern detected: {pattern}",
                    severity="high"
                )
                return True
        return False
    
    def detect_injection_attempt(self, input_value: str) -> bool:
        """Detect potential injection attack patterns."""
        injection_patterns = [
            r"<script[^>]*>",  # XSS
            r"javascript:",  # XSS
            r"on\w+\s*=",  # Event handler injection
            r"';.*--",  # SQL injection
            r"UNION\s+SELECT",  # SQL injection
            r"\|\s*[a-z]+",  # Command injection
            r";\s*[a-z]+",  # Command injection
        ]
        
        for pattern in injection_patterns:
            if re.search(pattern, input_value, re.IGNORECASE):
                self.log_potential_attack(
                    "injection",
                    f"Potential injection attempt detected: pattern {pattern}",
                    severity="high"
                )
                return True
        return False


# Global logger instance
_logger_instance = None

def get_security_logger() -> SecurityLogger:
    """Get or create the global security logger instance."""
    global _logger_instance
    if _logger_instance is None:
        _logger_instance = SecurityLogger()
    return _logger_instance
