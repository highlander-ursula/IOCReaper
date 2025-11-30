# Quick Command Reference

## 🐳 Docker Commands

```bash
# Build the image
docker-compose build

# Start the application
docker-compose up

# Start in background
docker-compose up -d

# View logs
docker-compose logs -f

# Stop the application
docker-compose down

# Restart
docker-compose restart

# Rebuild and start
docker-compose up --build

# Remove everything (including volumes)
docker-compose down -v
```

## 💻 Manual Setup Commands

```bash
# Create virtual environment
python3 -m venv venv

# Activate (macOS/Linux)
source venv/bin/activate

# Activate (Windows)
venv\Scripts\activate

# Install dependencies
pip install -r app/requirements.txt

# Create logs directory
mkdir -p logs

# Run application
cd app
python main.py

# Deactivate virtual environment
deactivate
```

## 🔧 Git Commands

```bash
# Initialize repository
git init

# Configure user
git config user.name "Your Name"
git config user.email "mmaddipa@umd.edu"

# Add all files
git add .

# Check status
git status

# Commit changes
git commit -m "Phase 5: Security Implementation"

# Create branch
git branch -M Phase5

# Add remote
git remote add origin https://github.com/highlander-ursula/IOCReaper.git

# Push to GitHub
git push -u origin Phase5

# Push with token
git push https://YOUR_TOKEN_HERE@github.com/highlander-ursula/IOCReaper.git Phase5

# Check remote
git remote -v

# View branches
git branch -a
```

## 🧪 Testing Commands

```bash
# Access application
open http://localhost:8000
# Or: curl http://localhost:8000

# Check health endpoint
curl http://localhost:8000/health

# View all logs
ls -la logs/

# View specific log
cat logs/user_actions.log
cat logs/security.log
cat logs/validation.log

# Tail logs (follow)
tail -f logs/security.log

# Check running containers
docker ps

# Check Python version
python --version

# Check installed packages
pip list

# Check specific package version
pip show python-multipart
pip show jinja2
```

## 🔍 Snyk Commands

```bash
# Install Snyk CLI
npm install -g snyk

# Authenticate
snyk auth

# Test dependencies
snyk test --file=app/requirements.txt

# Monitor project
snyk monitor

# View vulnerabilities
snyk test --json
```

## 🔧 Troubleshooting Commands

```bash
# Find process using port 8000
lsof -i :8000

# Kill process
kill -9 <PID>

# Check Docker status
docker ps -a

# View Docker logs
docker logs iocreaper

# Clean Docker system
docker system prune -a

# Check disk space
df -h

# Check Python path
which python
which python3

# Verify pip
pip --version

# Update pip
pip install --upgrade pip

# Fix permissions (macOS/Linux)
chmod 755 logs
chown -R $USER logs

# View environment variables
env | grep PYTHON
```

## 📦 Package Management

```bash
# List installed packages
pip list

# Show package info
pip show <package-name>

# Install specific version
pip install <package>==<version>

# Upgrade package
pip install --upgrade <package>

# Uninstall package
pip uninstall <package>

# Freeze requirements
pip freeze > requirements.txt

# Install from requirements
pip install -r requirements.txt
```

## 🚀 Quick Start (3 Commands)

```bash
cd IOCReaper_Phase5_FINAL
docker-compose up
# Open http://localhost:8000
```

## 📝 File Operations

```bash
# List files
ls -la

# View file content
cat <filename>

# Edit file (macOS/Linux)
nano <filename>
vim <filename>

# Edit file (Windows)
notepad <filename>

# Search in files
grep -r "search_term" .

# Find files
find . -name "*.py"

# Count lines of code
find . -name "*.py" | xargs wc -l
```

## 🔄 Common Workflows

### First Time Setup
```bash
cd IOCReaper_Phase5_FINAL
docker-compose build
docker-compose up -d
curl http://localhost:8000/health
```

### Daily Development
```bash
docker-compose up
# Make changes
docker-compose restart
docker-compose logs -f
```

### Push to GitHub
```bash
git add .
git commit -m "Your message"
git push origin Phase5
```

### Verify Security
```bash
snyk test --file=app/requirements.txt
cat logs/security.log
curl -I http://localhost:8000
```

### Clean Restart
```bash
docker-compose down
docker system prune -f
docker-compose build --no-cache
docker-compose up
```

## 💡 Tips

- Use `docker-compose up -d` to run in background
- Use `Ctrl+C` to stop foreground processes
- Use `docker-compose logs -f` to follow logs
- Always activate virtual environment before pip commands
- Check logs/ directory for security events
- Run Snyk scan before committing

---

**Last Updated:** November 30, 2025
