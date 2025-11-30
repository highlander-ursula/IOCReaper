"""
IOCReaper Secure Error Handler Module
Phase 5 Security Implementation

Mitigates:
- MC-006: Export Format Manipulation for Code Execution
- Information disclosure through error messages
- Stack trace exposure

Implements:
- SR-13: Gracefully handle invalid or oversized inputs
- SR-14: Suppress technical details in user-facing errors
- SR-15: Implement centralized exception handling

Author: Manudeep Maddipatla
Email: mmaddipa@umd.edu
UMD Directory ID: mmaddipa (121417350)
"""

import traceback
import sys
from typing import Dict, Any, Optional
from security_logger import get_security_logger


class SecureErrorHandler:
    """
    Centralized error handling that prevents information disclosure.
    
    Provides user-friendly error messages while logging detailed
    information securely server-side.
    """
    
    # Generic error messages for different categories
    GENERIC_MESSAGES = {
        "validation": "Invalid input provided. Please check your input and try again.",
        "extraction": "Failed to extract IOCs. Please verify your input text.",
        "export": "Failed to generate export file. Please try again.",
        "search": "Search operation failed. Please try again.",
        "tag": "Failed to manage tags. Please try again.",
        "session": "Session operation failed. Please try again.",
        "internal": "An internal error occurred. Please try again later.",
        "rate_limit": "Too many requests. Please wait before trying again.",
    }
    
    def __init__(self):
        """Initialize the error handler."""
        self.logger = get_security_logger()
    
    def handle_validation_error(self, error: Exception, context: str = "") -> Dict[str, Any]:
        """
        Handle validation errors.
        
        Args:
            error: The validation error
            context: Additional context about the error
            
        Returns:
            Dict with user-safe error response
        """
        # Log detailed error
        self.logger.log_error(
            "validation_error",
            f"{context}: {str(error)}",
            traceback.format_exc()
        )
        
        # Return generic message to user
        return {
            "error": self.GENERIC_MESSAGES["validation"],
            "status": "error",
            "error_type": "validation"
        }
    
    def handle_extraction_error(self, error: Exception, text_size: int = 0) -> Dict[str, Any]:
        """
        Handle IOC extraction errors.
        
        Args:
            error: The extraction error
            text_size: Size of input text
            
        Returns:
            Dict with user-safe error response
        """
        # Log detailed error
        self.logger.log_error(
            "extraction_error",
            f"Text size: {text_size}, Error: {str(error)}",
            traceback.format_exc()
        )
        
        # Provide specific message for known error types
        if "exceeds" in str(error).lower() and "limit" in str(error).lower():
            return {
                "error": "Input size exceeds maximum limit. Please use smaller text.",
                "status": "error",
                "error_type": "size_limit"
            }
        elif "empty" in str(error).lower():
            return {
                "error": "Input text cannot be empty.",
                "status": "error",
                "error_type": "empty_input"
            }
        else:
            return {
                "error": self.GENERIC_MESSAGES["extraction"],
                "status": "error",
                "error_type": "extraction"
            }
    
    def handle_export_error(self, error: Exception, format: str = "") -> Dict[str, Any]:
        """
        Handle export errors.
        
        Args:
            error: The export error
            format: Export format being used
            
        Returns:
            Dict with user-safe error response
        """
        # Log detailed error
        self.logger.log_error(
            "export_error",
            f"Format: {format}, Error: {str(error)}",
            traceback.format_exc()
        )
        
        return {
            "error": self.GENERIC_MESSAGES["export"],
            "status": "error",
            "error_type": "export"
        }
    
    def handle_search_error(self, error: Exception, query: str = "") -> Dict[str, Any]:
        """
        Handle search errors.
        
        Args:
            error: The search error
            query: Search query (sanitized, first 50 chars only)
            
        Returns:
            Dict with user-safe error response
        """
        # Log detailed error with sanitized query
        self.logger.log_error(
            "search_error",
            f"Query (first 50 chars): {query[:50]}, Error: {str(error)}",
            traceback.format_exc()
        )
        
        return {
            "error": self.GENERIC_MESSAGES["search"],
            "status": "error",
            "error_type": "search"
        }
    
    def handle_tag_error(self, error: Exception, operation: str = "") -> Dict[str, Any]:
        """
        Handle tag management errors.
        
        Args:
            error: The tag error
            operation: Tag operation being performed
            
        Returns:
            Dict with user-safe error response
        """
        # Log detailed error
        self.logger.log_error(
            "tag_error",
            f"Operation: {operation}, Error: {str(error)}",
            traceback.format_exc()
        )
        
        # Provide specific message for known validation errors
        error_msg = str(error).lower()
        if "empty" in error_msg:
            return {
                "error": "Tag cannot be empty.",
                "status": "error",
                "error_type": "tag_validation"
            }
        elif "forbidden" in error_msg or "invalid" in error_msg:
            return {
                "error": "Tag contains invalid characters.",
                "status": "error",
                "error_type": "tag_validation"
            }
        elif "not found" in error_msg:
            return {
                "error": "IOC not found.",
                "status": "error",
                "error_type": "not_found"
            }
        elif "limit" in error_msg or "maximum" in error_msg:
            return {
                "error": "Maximum number of tags reached for this IOC.",
                "status": "error",
                "error_type": "limit_exceeded"
            }
        else:
            return {
                "error": self.GENERIC_MESSAGES["tag"],
                "status": "error",
                "error_type": "tag"
            }
    
    def handle_session_error(self, error: Exception, operation: str = "") -> Dict[str, Any]:
        """
        Handle session management errors.
        
        Args:
            error: The session error
            operation: Session operation being performed
            
        Returns:
            Dict with user-safe error response
        """
        # Log detailed error
        self.logger.log_error(
            "session_error",
            f"Operation: {operation}, Error: {str(error)}",
            traceback.format_exc()
        )
        
        return {
            "error": self.GENERIC_MESSAGES["session"],
            "status": "error",
            "error_type": "session"
        }
    
    def handle_internal_error(self, error: Exception, context: str = "") -> Dict[str, Any]:
        """
        Handle unexpected internal errors.
        
        Args:
            error: The internal error
            context: Context in which error occurred
            
        Returns:
            Dict with user-safe error response
        """
        # Log detailed error
        self.logger.log_error(
            "internal_error",
            f"Context: {context}, Error: {str(error)}",
            traceback.format_exc()
        )
        
        # Log as exception for additional tracking
        self.logger.log_exception(error, context)
        
        return {
            "error": self.GENERIC_MESSAGES["internal"],
            "status": "error",
            "error_type": "internal"
        }
    
    def handle_rate_limit_error(self, action: str, count: int, window: int) -> Dict[str, Any]:
        """
        Handle rate limit exceeded errors.
        
        Args:
            action: Action that was rate limited
            count: Number of requests
            window: Time window in seconds
            
        Returns:
            Dict with user-safe error response
        """
        # Log rate limit event
        self.logger.log_rate_limit_exceeded(action, count, window)
        
        return {
            "error": self.GENERIC_MESSAGES["rate_limit"],
            "status": "error",
            "error_type": "rate_limit"
        }
    
    def create_success_response(self, message: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Create a standardized success response.
        
        Args:
            message: Success message
            data: Optional data to include
            
        Returns:
            Dict with success response
        """
        response = {
            "status": "success",
            "message": message
        }
        
        if data is not None:
            response.update(data)
        
        return response
    
    @staticmethod
    def sanitize_error_message(error_msg: str) -> str:
        """
        Sanitize error message to remove sensitive information.
        
        Args:
            error_msg: Original error message
            
        Returns:
            Sanitized error message
        """
        # Remove file paths
        sanitized = re.sub(r'[/\\][a-zA-Z0-9_/\\.-]+', '[PATH]', error_msg)
        
        # Remove line numbers
        sanitized = re.sub(r'line \d+', 'line [NUM]', sanitized)
        
        # Remove memory addresses
        sanitized = re.sub(r'0x[0-9a-fA-F]+', '0x[ADDR]', sanitized)
        
        return sanitized


# Global error handler instance
_error_handler_instance = None

def get_error_handler() -> SecureErrorHandler:
    """Get or create the global error handler instance."""
    global _error_handler_instance
    if _error_handler_instance is None:
        _error_handler_instance = SecureErrorHandler()
    return _error_handler_instance
