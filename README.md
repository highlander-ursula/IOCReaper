# IOCReaper

[![Docker](https://img.shields.io/badge/Docker-Ready-blue)]()
[![Python](https://img.shields.io/badge/Python-3.11+-blue)]()

A production-ready web application for extracting and analyzing Indicators of Compromise (IOCs) from threat intelligence text.

## 🚀 Quick Start with Docker

### Prerequisites

- Docker Desktop installed
- Docker Compose (included with Docker Desktop)

### 3-Step Setup

```bash
# 1. Navigate to project directory
cd IOCReaper_Phase5_FINAL

# 2. Build and start
docker-compose up --build

# 3. Access the application
# Open: http://localhost:8000
```

That's it! 🎉

## 📦 Installation Options

### Option 1: Docker (Recommended)

```bash
# Build the image
docker-compose build

# Start the container
docker-compose up

# Run in background
docker-compose up -d

# Stop the container
docker-compose down
```

### Option 2: Manual Setup

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate
# On Windows:
venv\Scripts\activate

# Install dependencies
pip install -r app/requirements.txt

# Create logs directory
mkdir logs

# Run the application
cd app
python main.py
```

## 🧪 Testing & Validation

### Test IOC Extraction

1. Open http://localhost:8000
2. Paste sample text:
   ```
   Contact admin@malicious-site.com
   Visit https://evil.com
   IP: 192.168.1.100
   Hash: 5d41402abc4b2a76b9719d911017c592
   ```
3. Click "Extract IOCs"
4. ✅ **Expected:** Results displayed in tabs

### Test CSV Export

1. Extract some IOCs
2. Click Export → CSV
3. Open in Excel
4. ✅ **Expected:** Data displays correctly

### Test Logging

```bash
# Check log files
ls logs/

# Should see:
# - user_actions.log
# - validation.log
# - errors.log
# - admin.log
# - security.log

# View security events
cat logs/security.log

# View user actions
cat logs/user_actions.log
```

## 📋 Project Structure

```
IOCReaper_Phase5_FINAL/
├── Dockerfile                      # Docker configuration
├── docker-compose.yml              # Docker Compose setup
├── .dockerignore                   # Docker build exclusions
├── .gitignore                      # Git exclusions
├── README.md                       # This file
├── SETUP_GUIDE.md                  # Detailed setup instructions
├── QUICK_COMMANDS.md               # Command reference
├── app/
│   ├── main.py                     # FastAPI application
│   ├── security_logger.py          # Security logging module
│   ├── input_validator.py          # Input validation module
│   ├── error_handler.py            # Error handling module
│   ├── ioc_parser.py               # IOC extraction
│   ├── exporter.py                 # Export functionality
│   ├── tag_manager.py              # Tag management
│   ├── searcher.py                 # Search functionality
│   ├── session_manager.py          # Session management
│   ├── categorizer.py              # IOC categorization
│   ├── fangerdefanger.py           # Defang/refang utilities
│   └── requirements.txt            # Python dependencies
├── static/
│   ├── css/
│   │   └── style.css               # Styling
│   └── js/
│       └── app.js                  # Frontend JavaScript
├── templates/
│   └── index.html                  # Main HTML template
└── logs/                           # Log files (created at runtime)
    ├── user_actions.log
    ├── validation.log
    ├── errors.log
    ├── admin.log
    └── security.log
```

## 🔧 Configuration

### Environment Variables

You can configure the application using environment variables in `docker-compose.yml`:

```yaml
environment:
  - APP_NAME=IOCReaper
  - APP_VERSION=2.0.0
  - ENVIRONMENT=production
  - LOG_LEVEL=INFO
```

### Ports

- Default: `8000`
- To change: Edit `docker-compose.yml` ports section

```yaml
ports:
  - "8080:8000"  # Change left side to desired port
```

## 📚 Documentation

- **SETUP_GUIDE.md** - Complete setup and deployment instructions
- **QUICK_COMMANDS.md** - Command reference sheet

## 🎯 Features

### IOC Extraction

- IPv4 and IPv6 addresses
- Domain names
- URLs
- Email addresses
- MD5, SHA1, and SHA256 hashes

### Operations

- Extract IOCs from text
- Normalize (defang to fang conversion)
- Deduplicate IOCs
- Tag management
- Search functionality
- Export (JSON, CSV, TXT)
- Session management

### Security

- Input validation and sanitization
- XSS prevention
- CSV formula injection protection
- Comprehensive logging
- Secure error handling

## 🐛 Troubleshooting

### Port Already in Use

```bash
# Find process using port 8000
lsof -i :8000

# Kill the process
kill -9 <PID>

# Or change port in docker-compose.yml
```

### Docker Build Fails

```bash
# Clean Docker cache
docker system prune -a

# Rebuild without cache
docker-compose build --no-cache
```

### Permission Issues

```bash
# Fix logs directory permissions
chmod 755 logs
```

## 📤 GitHub Upload

```bash
# Initialize Git (if not done)
git init

# Add all files
git add .

# Commit
git commit -m "Phase 5: Complete IOCReaper implementation"

# Create branch
git branch -M Phase5

# Add remote
git remote add origin https://github.com/highlander-ursula/IOCReaper.git

# Push
git push -u origin Phase5
```

## 👨‍💻 Author

**Manudeep Maddipatla**
- Email: mmaddipa@umd.edu
- UMD Directory ID: 121417350
- Course: ENPM680 - Introduction to Secure Software Engineering

## 📄 License

This project is part of academic coursework at the University of Maryland.

## 🙏 Acknowledgments

- ENPM680 Course Staff
- OWASP for security guidelines
- FastAPI and Bootstrap communities

---

**Last Updated:** November 30, 2025  
**Version:** 2.0.0
