from typing import Dict

class SessionManager:
    def __init__(self):
        self.ioc_store = {}
    
    def store_iocs(self, iocs: Dict):
        """Store IOCs in memory"""
        self.ioc_store = iocs
    
    def get_iocs(self) -> Dict:
        """Retrieve stored IOCs"""
        return self.ioc_store
    
    def clear(self):
        """Clear session data"""
        self.ioc_store = {}
```

3. **Save**

---

#### **File 9: requirements.txt**

1. Create: `requirements.txt`
2. Paste:
```
fastapi==0.104.1
uvicorn==0.24.0
python-multipart==0.0.6
jinja2==3.1.2
```

3. **Save**

---

#### **File 10: .gitignore**

1. Create: `.gitignore` (note the dot at the beginning)
2. Paste:
```
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
venv/
ENV/
.venv
.env
*.log
.pytest_cache/
.coverage
htmlcov/