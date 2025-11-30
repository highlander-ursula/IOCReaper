# IOCReaper - Complete Setup & Deployment Guide

**Author:** Manudeep Maddipatla (mmaddipa@umd.edu)  
**Course:** ENPM680 - Introduction to Secure Software Engineering  
**Date:** November 30, 2025

---

## 📋 Table of Contents

1. [Download the Application](#1-download-the-application)
2. [Run with Docker](#2-run-with-docker-recommended)
3. [Run Without Docker](#3-run-without-docker)
4. [Validate Security Fixes](#4-validate-security-fixes)
5. [Push to GitHub](#5-push-to-github)
6. [Troubleshooting](#6-troubleshooting)

---

## 1. Download the Application

### Method A: Download from Outputs

Download the complete `IOCReaper_Phase5_FINAL` folder from Claude's outputs to your local machine.

Extract to a location such as:
- macOS/Linux: `/Users/yourname/IOCReaper_Phase5_FINAL`
- Windows: `C:\Users\yourname\IOCReaper_Phase5_FINAL`

### Method B: Clone from GitHub (After Upload)

```bash
git clone https://github.com/highlander-ursula/IOCReaper.git
cd IOCReaper
git checkout Phase5
```

---

## 2. Run with Docker (Recommended)

### Prerequisites

- **Docker Desktop** installed
  - Download from: https://www.docker.com/products/docker-desktop
  - Includes Docker Compose automatically
  
- **System Requirements:**
  - 4GB RAM minimum
  - 2GB free disk space

### Step-by-Step Instructions

#### Step 1: Open Terminal/Command Prompt

**macOS:**
- Applications → Utilities → Terminal

**Windows:**
- Start → type "cmd" → Command Prompt

**Linux:**
- Ctrl + Alt + T

#### Step 2: Navigate to Project Directory

```bash
cd /path/to/IOCReaper_Phase5_FINAL
```

Replace `/path/to` with your actual path.

#### Step 3: Verify Files

```bash
# List files
ls -la

# Should see:
# - Dockerfile
# - docker-compose.yml
# - app/
# - static/
# - templates/
```

#### Step 4: Build the Docker Image

```bash
docker-compose build
```

**What this does:**
- Creates a Python 3.11 environment
- Installs all dependencies
- Sets up security configurations
- Creates a non-root user

**Expected output:**
```
Building iocreaper
Step 1/15 : FROM python:3.11-slim as builder
...
Successfully built [image-id]
Successfully tagged iocreaper:phase5
```

**Time:** 2-5 minutes

#### Step 5: Start the Application

```bash
docker-compose up
```

**For background mode:**
```bash
docker-compose up -d
```

**Expected output:**
```
Creating network "iocreaper_iocreaper-network" with driver "bridge"
Creating iocreaper ... done
Attaching to iocreaper
iocreaper  | INFO:     Started server process [1]
iocreaper  | INFO:     Waiting for application startup.
iocreaper  | INFO:     Application startup complete.
iocreaper  | INFO:     Uvicorn running on http://127.0.0.1:8000
```

#### Step 6: Access the Application

Open your web browser and go to:

```
http://localhost:8000
```

You should see the IOCReaper interface with:
- Input text area
- Extraction options

#### Step 7: Test Basic Functionality

1. **Paste sample text:**
   ```
   Contact admin@malicious-site[.]com
   Visit hxxps://evil[.]com
   Hash: 5d41402abc4b2a76b9719d911017c592
   IP: 192.168.1.100
   ```

2. **Click "Extract IOCs"**

3. **Verify results appear** in tabs (IP, Domain, Email, Hash)

#### Step 8: View Logs

```bash
# View container logs
docker-compose logs -f

# View application logs
ls logs/
cat logs/user_actions.log
cat logs/security.log
```

#### Step 9: Stop the Application

```bash
# Stop containers
docker-compose down

# Stop and remove volumes
docker-compose down -v
```

---

## 3. Run Without Docker

### Prerequisites

- **Python 3.11+** installed
  - Download from: https://www.python.org/downloads/
  
- **pip** package manager (included with Python)

### Step-by-Step Instructions

#### Step 1: Open Terminal

Follow instructions from Docker section above.

#### Step 2: Navigate to Project Directory

```bash
cd /path/to/IOCReaper_Phase5_FINAL
```

#### Step 3: Create Virtual Environment

```bash
python3 -m venv venv
```

**On Windows (if python3 doesn't work):**
```bash
python -m venv venv
```

#### Step 4: Activate Virtual Environment

**macOS/Linux:**
```bash
source venv/bin/activate
```

**Windows:**
```bash
venv\Scripts\activate
```

You should see `(venv)` prefix in your terminal.

#### Step 5: Verify Python Version

```bash
python --version

# Should show: Python 3.11.x or higher
```

#### Step 6: Install Dependencies

```bash
pip install -r app/requirements.txt
```

**Expected packages installed:**
- fastapi==0.104.1
- uvicorn==0.24.0
- python-multipart==0.0.9
- jinja2==3.1.5
- pydantic==2.5.0
- pytest==7.4.3
- httpx==0.25.1

#### Step 7: Create Logs Directory

```bash
mkdir -p logs
```

**On Windows:**
```bash
mkdir logs
```

#### Step 8: Run the Application

```bash
cd app
python main.py
```

**Expected output:**
```
INFO:     Started server process
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8000
```

#### Step 9: Access the Application

Open browser to:
```
http://127.0.0.1:8000
```

#### Step 10: Stop the Application

Press `Ctrl + C` in the terminal

---

## 4. Validate Security Fixes

### Test 1: XSS Prevention

**Objective:** Verify DOM-based XSS is fixed

1. Open http://localhost:8000
2. Paste in input box:
   ```html
   <script>alert('XSS Test')</script>
   <img src=x onerror=alert('XSS')>
   <div onclick=alert('XSS')>Click me</div>
   ```
3. Click "Extract IOCs"

✅ **Expected Result:**
- No JavaScript alert boxes appear
- Text displays safely as plain text
- No script execution

❌ **If Alert Appears:** XSS fix not applied correctly

### Test 2: Python-multipart Version Check

**Objective:** Verify upgraded dependency

```bash
# Check installed version
pip show python-multipart

# Expected:
# Version: 0.0.9 (not 0.0.6)
```

### Test 3: Jinja2 Version Check

**Objective:** Verify upgraded dependency

```bash
# Check installed version
pip show jinja2

# Expected:
# Version: 3.1.5 (not 3.1.2)
```

### Test 4: CSV Formula Injection Prevention

**Objective:** Verify export protection

1. Extract IOCs from:
   ```
   =cmd|'/c calc'!A1
   +SUM(A1:A10)
   -2+3+cmd|'/c calc'!A1
   @SUM(A1:A10)
   |calc
   ```

2. Click Export → CSV
3. Open the downloaded CSV in Excel
4. Look at the cells

✅ **Expected Result:**
- All formulas have ' prefix
- Formulas display as text
- Calculator doesn't launch

❌ **If Calculator Launches:** CSV protection not working

### Test 5: Input Validation

**Objective:** Verify malicious input is blocked

1. Try SQL injection:
   ```
   '; DROP TABLE users--
   1' OR '1'='1
   ```

2. Click "Extract IOCs"

✅ **Expected Result:**
- Error message or safe handling
- Entry in `logs/validation.log`

### Test 6: Logging Verification

**Objective:** Verify all log files are created

```bash
# Check logs directory
ls -la logs/

# Should see:
# user_actions.log
# validation.log
# errors.log
# admin.log
# security.log
```

View log contents:
```bash
# User actions
cat logs/user_actions.log

# Security events
cat logs/security.log

# Validation failures
cat logs/validation.log
```

✅ **Expected:** JSON-formatted log entries with timestamps

### Test 7: Security Headers

**Objective:** Verify HTTP security headers

```bash
curl -I http://localhost:8000
```

✅ **Expected headers:**
```
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Cache-Control: no-store, no-cache, must-revalidate
Content-Security-Policy: default-src 'self'...
```

---

## 5. Push to GitHub

### Prerequisites

- Git installed
- GitHub account
- Personal Access Token (generate at https://github.com/settings/tokens)

### Step-by-Step Instructions

#### Step 1: Initialize Git Repository

```bash
cd /path/to/IOCReaper_Phase5_FINAL
git init
```

#### Step 2: Configure Git (If First Time)

```bash
git config user.name "Your Name"
git config user.email "mmaddipa@umd.edu"
```

#### Step 3: Add All Files

```bash
git add .
```

#### Step 4: Check What Will Be Committed

```bash
git status
```

Should show all project files in green.

#### Step 5: Create Commit

```bash
git commit -m "Phase 5: Security Implementation

- Fixed all vulnerabilities (XSS, ReDoS, jinja2)
- Added Docker and docker-compose configuration
- Enhanced XSS protection in frontend (app.js)
- Upgraded dependencies (jinja2 3.1.2→3.1.5, python-multipart 0.0.6→0.0.9)
- Implemented comprehensive security logging (5 log files)
- CSV formula injection prevention
- All 13 misuse cases mitigated
- Production-ready with security hardening"
```

#### Step 6: Create Phase5 Branch

```bash
git branch -M Phase5
```

#### Step 7: Add Remote Repository

```bash
git remote add origin https://github.com/highlander-ursula/IOCReaper.git
```

#### Step 8: Push to GitHub

```bash
git push https://YOUR_TOKEN_HERE@github.com/highlander-ursula/IOCReaper.git Phase5
```

Replace `YOUR_TOKEN_HERE` with your actual Personal Access Token.

**Alternative (if you've configured credentials):**
```bash
git push -u origin Phase5
```

#### Step 9: Verify on GitHub

1. Go to https://github.com/highlander-ursula/IOCReaper
2. Click "Branch" dropdown
3. Select "Phase5"
4. Verify all files are present

#### Step 10: ⚠️ DELETE TOKEN

**CRITICAL SECURITY STEP:**

After successful push, immediately:
1. Go to GitHub → Settings → Developer settings → Personal access tokens
2. Find your token
3. Click "Revoke"
4. Confirm revocation

---

## 6. Troubleshooting

### Issue: Docker Build Fails

**Error:** `Cannot connect to Docker daemon`

**Solution:**
```bash
# Start Docker Desktop
# Wait for it to fully start
# Try again
docker-compose build
```

### Issue: Port 8000 Already in Use

**Error:** `bind: address already in use`

**Solution:**
```bash
# Find process using port 8000
lsof -i :8000

# Kill the process
kill -9 <PID>

# Or change port in docker-compose.yml
ports:
  - "8080:8000"
```

### Issue: Permission Denied on Logs

**Error:** `Permission denied: 'logs/user_actions.log'`

**Solution:**
```bash
# Fix permissions
chmod 755 logs
chown -R $USER logs

# Or on Windows, run as Administrator
```

### Issue: Module Not Found

**Error:** `ModuleNotFoundError: No module named 'fastapi'`

**Solution:**
```bash
# Activate virtual environment
source venv/bin/activate  # macOS/Linux
venv\Scripts\activate      # Windows

# Reinstall dependencies
pip install -r app/requirements.txt
```

### Issue: Health Check Failing

**Error:** Container restarting, health check fails

**Solution:**
```bash
# Check logs
docker-compose logs

# Ensure application is running
curl http://localhost:8000/health

# Should return: {"status": "healthy"}
```

---

## ✅ Verification Checklist

Before submitting, verify:

- [ ] Docker image builds successfully
- [ ] Application starts without errors
- [ ] Can access http://localhost:8000
- [ ] IOC extraction works
- [ ] XSS attempts are blocked/sanitized
- [ ] CSV export doesn't execute formulas
- [ ] All 5 log files are created
- [ ] Code pushed to GitHub Phase5 branch
- [ ] GitHub token revoked

---

## 📞 Need Help?

If you encounter issues:

1. Check this troubleshooting section
2. Review Docker/application logs
3. Verify all files are present
4. Check Python and Docker versions
5. Ensure ports are available

---

**Setup Guide Complete!** 🎉

You now have a fully functional, security-enhanced IOC extraction application ready for deployment and review.

---

**Last Updated:** November 30, 2025  
**Version:** 2.0.0
