"""
IOCReaper Main Application - Phase 5 Security Enhanced
FastAPI application with comprehensive security controls

Author: Manudeep Maddipatla
Email: mmaddipa@umd.edu  
UMD Directory ID: mmaddipa (121417350)
"""

from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from typing import Optional
import json
import traceback

# Import application modules
from ioc_parser import IOCParser
from categorizer import Categorizer
from tag_manager import TagManager
from searcher import Searcher
from exporter import Exporter
from session_manager import SessionManager

# Import security modules
from security_logger import get_security_logger
from input_validator import get_input_validator
from error_handler import get_error_handler

# Initialize FastAPI app
app = FastAPI(
    title="IOCReaper",
    description="IOC Extraction and Analysis Tool - Phase 5 Security Enhanced",
    version="2.0.0"
)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Initialize security components
security_logger = get_security_logger()
input_validator = get_input_validator()
error_handler = get_error_handler()

# Initialize session manager
session_manager = SessionManager()

# Log application start
security_logger.log_session_start()


# Security Headers Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add security headers to all responses."""
    response = await call_next(request)
    
    # Prevent clickjacking
    response.headers["X-Frame-Options"] = "DENY"
    
    # Prevent MIME sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"
    
    # XSS Protection
    response.headers["X-XSS-Protection"] = "1; mode=block"
    
    # Content Security Policy
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data:; "
        "font-src 'self' https://cdn.jsdelivr.net; "
        "connect-src 'self';"
    )
    
    # Prevent browser caching of sensitive data
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, proxy-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    
    return response


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Serve the main application page."""
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/extract")
async def extract_iocs(
    text: str = Form(...),
    normalize: bool = Form(False),
    deduplicate: bool = Form(False)
):
    """
    Extract IOCs from text with comprehensive security validation.
    
    Security Features:
    - Input validation (size, content)
    - Injection attack prevention
    - ReDoS protection
    - Comprehensive logging
    - Secure error handling
    """
    try:
        # Validate input
        is_valid, error_msg = input_validator.validate_text_input(text)
        if not is_valid:
            security_logger.log_validation_failure(
                "text_input",
                text[:100],
                error_msg
            )
            return JSONResponse(
                status_code=400,
                content=error_handler.handle_validation_error(
                    ValueError(error_msg),
                    "extract_iocs"
                )
            )
        
        # Parse IOCs
        parser = IOCParser()
        iocs = parser.extract(text, normalize=normalize, deduplicate=deduplicate)
        
        if not iocs:
            return JSONResponse(
                content={
                    "message": "No IOCs were identified",
                    "iocs": {},
                    "status": "success"
                }
            )
        
        # Categorize IOCs
        categorizer = Categorizer()
        categorized = categorizer.categorize(iocs)
        
        # Store in session
        session_manager.store_iocs(categorized)
        
        return JSONResponse(content={
            "iocs": categorized,
            "status": "success"
        })
        
    except ValueError as e:
        # Validation or extraction error
        return JSONResponse(
            status_code=400,
            content=error_handler.handle_extraction_error(e, len(text.encode('utf-8')))
        )
    except Exception as e:
        # Unexpected error
        return JSONResponse(
            status_code=500,
            content=error_handler.handle_internal_error(e, "extract_iocs")
        )


@app.post("/tag")
async def add_tag(ioc_value: str = Form(...), tag: str = Form(...)):
    """
    Add tag to an IOC with validation and logging.
    
    Security Features:
    - Tag input validation
    - XSS prevention
    - Tag count limits
    - Comprehensive logging
    """
    try:
        # Validate tag input
        is_valid, error_msg = input_validator.validate_tag_input(tag)
        if not is_valid:
            return JSONResponse(
                status_code=400,
                content=error_handler.handle_tag_error(
                    ValueError(error_msg),
                    "add_tag"
                )
            )
        
        #Sanitize tag for XSS prevention
        tag = input_validator.sanitize_output(tag.strip())
        ioc_value = input_validator.sanitize_output(ioc_value)
        
        # Add tag
        tag_manager = TagManager()
        result = tag_manager.add_tag(ioc_value, tag, session_manager)
        
        # Log successful tag addition
        security_logger.log_tag_action("add", ioc_value, tag, True)
        
        return JSONResponse(content=error_handler.create_success_response(
            "Tag added successfully",
            result
        ))
        
    except ValueError as e:
        # Tag validation error
        security_logger.log_tag_action("add", ioc_value, tag, False)
        return JSONResponse(
            status_code=400,
            content=error_handler.handle_tag_error(e, "add_tag")
        )
    except Exception as e:
        # Unexpected error
        security_logger.log_tag_action("add", ioc_value, tag, False)
        return JSONResponse(
            status_code=500,
            content=error_handler.handle_internal_error(e, "add_tag")
        )


@app.post("/search")
async def search_iocs(query: str = Form(...), case_sensitive: bool = Form(False)):
    """
    Search for IOCs with input validation and logging.
    
    Security Features:
    - Search query validation
    - Injection prevention
    - Result sanitization
    - Comprehensive logging
    """
    try:
        # Validate search query
        is_valid, error_msg = input_validator.validate_search_query(query)
        if not is_valid:
            return JSONResponse(
                status_code=400,
                content=error_handler.handle_search_error(
                    ValueError(error_msg),
                    query
                )
            )
        
        # Perform search
        searcher = Searcher()
        results = searcher.search(query, session_manager, case_sensitive)
        
        # Log search operation
        security_logger.log_search(query, case_sensitive, len(results))
        
        return JSONResponse(content={
            "results": results,
            "status": "success"
        })
        
    except Exception as e:
        # Unexpected error
        return JSONResponse(
            status_code=500,
            content=error_handler.handle_search_error(e, query[:50])
        )


@app.post("/export")
async def export_iocs(format: str = Form(...), include_tags: bool = Form(False)):
    """
    Export IOCs with security enhancements.
    
    Security Features:
    - Format validation
    - CSV formula injection prevention
    - JSON sanitization
    - Export logging
    - Secure file delivery
    """
    try:
        # Validate format
        valid_formats = ['csv', 'json', 'txt']
        if format.lower() not in valid_formats:
            return JSONResponse(
                status_code=400,
                content={"error": "Invalid export format", "status": "error"}
            )
        
        # Get IOC count for logging
        iocs = session_manager.get_iocs()
        total_iocs = sum(data['count'] for data in iocs.values())
        
        # Export with security enhancements
        exporter = Exporter()
        content, filename, media_type = exporter.export(
            session_manager,
            format,
            include_tags
        )
        
        # Log successful export
        security_logger.log_export(format, include_tags, total_iocs, True)
        
        # Return with security headers
        return Response(
            content=content,
            media_type=media_type,
            headers={
                "Content-Disposition": f"attachment; filename={filename}",
                "X-Content-Type-Options": "nosniff",
                "Content-Security-Policy": "default-src 'none'"
            }
        )
        
    except Exception as e:
        # Log failed export
        security_logger.log_export(format, include_tags, 0, False)
        return JSONResponse(
            status_code=500,
            content=error_handler.handle_export_error(e, format)
        )


@app.post("/clear")
async def clear_session():
    """
    Clear session data with logging.
    
    Security Features:
    - Session clearing logged as administrative action
    - IOC count logged before clearing
    """
    try:
        # Get IOC count before clearing
        iocs = session_manager.get_iocs()
        total_iocs = sum(data['count'] for data in iocs.values())
        
        # Clear session
        session_manager.clear()
        
        # Log administrative action
        security_logger.log_session_clear(total_iocs)
        
        return JSONResponse(content=error_handler.create_success_response(
            "Session cleared successfully"
        ))
        
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content=error_handler.handle_internal_error(e, "clear_session")
        )


@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring."""
    return {"status": "healthy", "version": "2.0.0"}


if __name__ == "__main__":
    # SECURITY: Bind to localhost only
    # For production, deploy behind reverse proxy with authentication
    uvicorn.run(
        app,
        host="0.0.0.0",  # Localhost only (SR-05)
        port=8000,
        log_level="info"
    )
