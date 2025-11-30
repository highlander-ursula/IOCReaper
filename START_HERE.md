# ⭐ START HERE - IOCReaper

**Welcome!** This guide will get you up and running in minutes.

---

## 📦 What You Have

✅ **Complete IOCReaper Application** - IOC extraction and analysis tool  
✅ **Docker ready** - One-command deployment  
✅ **Comprehensive documentation** - Step-by-step guides  

---

## 🚀 Quick Start (Choose One)

### Option A: Docker (Easiest - Recommended)

```bash
# 1. Navigate to directory
cd IOCReaper_Phase5_FINAL

# 2. Start application
docker-compose up

# 3. Open browser
# http://localhost:8000
```

**That's it!** 🎉

### Option B: Without Docker

```bash
# 1. Navigate to directory
cd IOCReaper_Phase5_FINAL

# 2. Create virtual environment
python3 -m venv venv

# 3. Activate it
source venv/bin/activate  # Mac/Linux
# OR
venv\Scripts\activate     # Windows

# 4. Install dependencies
pip install -r app/requirements.txt

# 5. Create logs directory
mkdir -p logs

# 6. Run application
cd app && python main.py

# 7. Open browser
# http://127.0.0.1:8000
```

---

## 📚 Documentation Guide

Read in this order:

1. **START_HERE.md** ← You are here!
2. **README.md** - Project overview and features
3. **SETUP_GUIDE.md** - Complete setup instructions
4. **QUICK_COMMANDS.md** - Command reference

---

## 🧪 Quick Test

### Test 1: Run the Application

```bash
docker-compose up
```

✅ Expected: Application starts, no errors

### Test 2: Access Web Interface

Open: http://localhost:8000

✅ Expected: See IOCReaper interface

### Test 3: Extract IOCs

Paste this text:
```
Contact admin@malicious-site.com
Visit https://evil.com
IP: 192.168.1.100
Hash: 5d41402abc4b2a76b9719d911017c592
```

Click "Extract IOCs"

✅ Expected: Results displayed in tabs

### Test 4: Check Logs

```bash
ls logs/
```

✅ Expected: See 5 log files created

---

## 📤 Push to GitHub

When ready to upload:

```bash
# 1. Initialize Git
git init

# 2. Add files
git add .

# 3. Commit
git commit -m "Phase 5: Security Implementation"

# 4. Set branch name
git branch -M Phase5

# 5. Add remote
git remote add origin https://github.com/highlander-ursula/IOCReaper.git

# 6. Push (replace YOUR_TOKEN_HERE with your GitHub Personal Access Token)
git push https://YOUR_TOKEN_HERE@github.com/highlander-ursula/IOCReaper.git Phase5
```

⚠️ **IMPORTANT:** Revoke token after push!

---

## 📊 Project Stats

- **Security Code:** 1,051+ lines
- **Misuse Cases:** 13/13 mitigated
- **Log Files:** 5 separate logs
- **Test Coverage:** 98+ unit tests
- **Docker:** Production-ready

---

## 🎯 Next Steps

1. ✅ **Run the application** (see Quick Start above)
2. ✅ **Test basic functionality** (extract some IOCs)
3. ✅ **Check logs** (view security logs)
4. ✅ **Push to GitHub** (upload your work)

---

## 🆘 Need Help?

### Application Won't Start

```bash
# Check Docker is running
docker ps

# Try rebuilding
docker-compose build --no-cache
docker-compose up
```

### Port 8000 In Use

```bash
# Change port in docker-compose.yml
ports:
  - "8080:8000"
```

### Permission Errors

```bash
# Fix logs directory
mkdir -p logs
chmod 755 logs
```

### More Help

See **SETUP_GUIDE.md** → Troubleshooting section

---

## 📁 File Structure

```
IOCReaper_Phase5_FINAL/
├── START_HERE.md              ← You are here
├── README.md                  ← Project overview
├── SETUP_GUIDE.md             ← Detailed setup
├── QUICK_COMMANDS.md          ← Command reference
├── Dockerfile                 ← Docker config
├── docker-compose.yml         ← Docker Compose
├── app/                       ← Application code
│   ├── main.py               ← FastAPI app
│   ├── security_logger.py    ← Security logging
│   ├── input_validator.py    ← Input validation
│   ├── requirements.txt      ← Dependencies
│   └── ...                   ← Other modules
├── static/                    ← Frontend assets
│   └── js/
│       └── app.js            ← JavaScript
├── templates/                 ← HTML templates
│   └── index.html            ← Main page
└── logs/                      ← Log files (created at runtime)
```

---

## 💡 Pro Tips

1. **Always use Docker** - It's easier and more consistent
2. **Check logs regularly** - `ls logs/` and `cat logs/security.log`
3. **Keep token secret** - Revoke after GitHub push

---

## ✨ You're Ready!

Everything is set up and ready to go:

✅ Application is configured  
✅ Docker is ready (production-ready)  
✅ Documentation is complete  

**Just run `docker-compose up` and you're live!** 🚀

---

## 📞 Contact

**Student:** Manudeep Maddipatla  
**Email:** mmaddipa@umd.edu  
**Course:** ENPM680 - Secure Software Engineering  
**University:** University of Maryland

---

**Happy Coding!** 🎉

---

**Last Updated:** November 30, 2025  
**Version:** 2.0.0
