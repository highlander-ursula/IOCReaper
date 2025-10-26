from fastapi import FastAPI, Request, Form
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse, Response
import uvicorn
from typing import Optional
import json

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Import our modules
from ioc_parser import IOCParser
from categorizer import Categorizer
from tag_manager import TagManager
from searcher import Searcher
from exporter import Exporter
from session_manager import SessionManager

# Initialize components
session_manager = SessionManager()

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/extract")
async def extract_iocs(
    text: str = Form(...),
    normalize: bool = Form(False),
    deduplicate: bool = Form(False)
):
    try:
        # Validate input size (100KB limit)
        if len(text.encode('utf-8')) > 100 * 1024:
            return JSONResponse(
                status_code=400,
                content={"error": "Input text exceeds 100KB limit"}
            )
        
        if not text.strip():
            return JSONResponse(
                status_code=400,
                content={"error": "Input text is empty"}
            )
        
        # Parse IOCs
        parser = IOCParser()
        iocs = parser.extract(text, normalize=normalize, deduplicate=deduplicate)
        
        if not iocs:
            return JSONResponse(
                content={"message": "No IOCs were identified", "iocs": {}}
            )
        
        # Categorize IOCs
        categorizer = Categorizer()
        categorized = categorizer.categorize(iocs)
        
        # Store in session
        session_manager.store_iocs(categorized)
        
        return JSONResponse(content={"iocs": categorized})
        
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"error": f"Extraction failed: {str(e)}"}
        )

@app.post("/tag")
async def add_tag(ioc_value: str = Form(...), tag: str = Form(...)):
    try:
        tag_manager = TagManager()
        result = tag_manager.add_tag(ioc_value, tag, session_manager)
        return JSONResponse(content=result)
    except Exception as e:
        return JSONResponse(
            status_code=400,
            content={"error": str(e)}
        )

@app.post("/search")
async def search_iocs(query: str = Form(...), case_sensitive: bool = Form(False)):
    try:
        searcher = Searcher()
        results = searcher.search(query, session_manager, case_sensitive)
        return JSONResponse(content={"results": results})
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"error": f"Search failed: {str(e)}"}
        )

@app.post("/export")
async def export_iocs(format: str = Form(...), include_tags: bool = Form(False)):
    try:
        exporter = Exporter()
        content, filename, media_type = exporter.export(
            session_manager,
            format,
            include_tags
        )
        
        return Response(
            content=content,
            media_type=media_type,
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"error": f"Export failed: {str(e)}"}
        )

@app.post("/clear")
async def clear_session():
    session_manager.clear()
    return JSONResponse(content={"message": "Session cleared successfully"})

if __name__ == "__main__":
       uvicorn.run(app, host="0.0.0.0", port=8000)