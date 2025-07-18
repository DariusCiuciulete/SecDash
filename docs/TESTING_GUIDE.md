# SecDash Testing Guide

## Overview

This guide provides comprehensive instructions for testing all security scanning functionality in SecDash. The application supports multiple security tools with detailed configurations and real-time monitoring.

## Supported Security Tools

### 🌐 Network Scanning
- **Nmap**: Network discovery, port scanning, service detection, vulnerability scanning
- **Tshark**: Network traffic analysis and protocol monitoring

### 🔒 Web Application Security
- **OWASP ZAP**: Web application vulnerability scanning (baseline, full, API)
- **Nikto**: Web server security scanning

### 🎯 Vulnerability Assessment
- **Nuclei**: Template-based vulnerability scanning (CVEs, misconfigurations)
- **OpenVAS**: Comprehensive vulnerability management
- **Metasploit**: Penetration testing and exploitation verification

## Quick Start

### 1. Automated Test Suite

Run the complete test suite:
```bash
# Run all tests automatically
python test_runner.py test

# Or run individual components
python test_runner.py backend    # Start backend services only
python test_runner.py webapp     # Start test web app only
```

### 2. Manual Testing Setup

Start all services manually:
```bash
# Terminal 1 - Infrastructure
docker-compose up -d postgres redis

# Terminal 2 - Backend API
cd backend
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Terminal 3 - Celery Worker
cd backend
celery -A celery_app worker --loglevel=info --pool=solo

# Terminal 4 - Test Web App
python test_webapp.py

# Terminal 5 - Frontend (optional)
cd frontend
npm start
```

## Test Scenarios

### A. Nmap Network Scanning Tests

#### A1. TCP SYN Scan
```json
{
  "asset_id": "your-asset-id",
  "tool": "nmap",
  "options": {
    "scan_type": "tcp_syn",
    "port_range": "1-1000",
    "timing": "-T4"
  }
}
```

**Expected Results:**
- Open ports: 22 (SSH), 80 (HTTP), 443 (HTTPS)
- Scan duration: 1-3 minutes
- Status progression: Queued → Running → Completed

#### A2. Service Detection Scan
```json
{
  "asset_id": "your-asset-id",
  "tool": "nmap",
  "options": {
    "scan_type": "service_detection",
    "port_range": "22,80,443",
    "timing": "-T4",
    "enable_scripts": true,
    "os_detection": true
  }
}
```

**Expected Results:**
- Service versions (e.g., "OpenSSH 7.4", "Apache 2.4.6")
- OS detection information
- Script scan results for additional details

#### A3. UDP Scan
```json
{
  "asset_id": "your-asset-id", 
  "tool": "nmap",
  "options": {
    "scan_type": "udp",
    "top_ports": "100",
    "timing": "-T4"
  }
}
```

**Expected Results:**
- Common UDP services (DNS, DHCP, NTP, SNMP)
- Longer scan duration (UDP is slower)
- Filtered ports indication

### B. ZAP Web Application Tests

#### B1. Baseline Scan
**Target:** `http://127.0.0.1:8080` (vulnerable test app)

```json
{
  "asset_id": "webapp-asset-id",
  "tool": "zap",
  "options": {
    "scan_type": "baseline",
    "spider_minutes": 2,
    "ajax_spider": false,
    "passive_scan": true
  }
}
```

**Expected Findings:**
- Cross-Site Scripting (XSS) on `/search`
- SQL Injection on `/login` 
- Missing security headers
- Insecure cookie settings

#### B2. Full Scan
```json
{
  "asset_id": "webapp-asset-id",
  "tool": "zap", 
  "options": {
    "scan_type": "full",
    "spider_minutes": 5,
    "ajax_spider": true,
    "passive_scan": true,
    "active_scan": true
  }
}
```

**Expected Results:**
- More comprehensive vulnerability detection
- Higher confidence ratings
- Additional attack vectors discovered

### C. Nuclei Template Scanning

#### C1. CVE Scan
```json
{
  "asset_id": "your-asset-id",
  "tool": "nuclei",
  "options": {
    "scan_type": "cve",
    "templates": ["cves"],
    "severity": ["medium", "high", "critical"]
  }
}
```

#### C2. Misconfiguration Scan
```json
{
  "asset_id": "your-asset-id",
  "tool": "nuclei",
  "options": {
    "scan_type": "misconfiguration",
    "templates": ["misconfigurations"],
    "severity": ["info", "low", "medium", "high"]
  }
}
```

### D. Additional Tool Tests

#### D1. Nikto Web Server Scan
```json
{
  "asset_id": "webapp-asset-id",
  "tool": "nikto",
  "options": {
    "scan_type": "web_scan",
    "check_outdated": true,
    "scan_cgi": true
  }
}
```

#### D2. Tshark Network Analysis
```json
{
  "asset_id": "network-asset-id", 
  "tool": "tshark",
  "options": {
    "scan_type": "network_capture",
    "duration": 60,
    "packet_count": 1000,
    "filter": "tcp or udp"
  }
}
```

## Test Assets

### Public Test Targets
- **scanme.nmap.org** (45.33.32.156) - Official Nmap test target
- **testphp.vulnweb.com** - Vulnerable web application

### Local Test Targets
- **127.0.0.1:8080** - SecDash test web application (vulnerable)
- **127.0.0.1** - Local machine for network scans
- **192.168.1.1** - Local router/gateway

## API Testing

### Creating Assets
```bash
curl -X POST "http://localhost:8000/api/v1/assets/" \
-H "Content-Type: application/json" \
-d '{
  "name": "Test Server",
  "type": "host",
  "target": "scanme.nmap.org",
  "description": "Test target for scanning"
}'
```

### Starting Scans
```bash
curl -X POST "http://localhost:8000/api/v1/scans/" \
-H "Content-Type: application/json" \
-d '{
  "asset_id": "your-asset-id",
  "tool": "nmap", 
  "options": {
    "scan_type": "tcp_syn",
    "port_range": "1-1000"
  }
}'
```

### Monitoring Scan Status
```bash
curl "http://localhost:8000/api/v1/scans/{scan-id}/status"
```

## Validation Checklist

### ✅ Backend Functionality
- [ ] API endpoints respond correctly
- [ ] Scan profiles are loaded
- [ ] Database connections work
- [ ] Celery workers are processing tasks

### ✅ Scan Execution
- [ ] Nmap scans complete successfully
- [ ] ZAP finds web vulnerabilities 
- [ ] Nuclei detects template matches
- [ ] All tools generate findings

### ✅ Data Processing
- [ ] Raw scan output is stored
- [ ] Findings are parsed correctly
- [ ] Vulnerabilities are deduplicated
- [ ] CVSS scores are calculated

### ✅ Real-time Monitoring
- [ ] Scan status updates in real-time
- [ ] Progress percentages increase
- [ ] Status messages are descriptive
- [ ] Completion notifications work

### ✅ Error Handling
- [ ] Invalid targets fail gracefully
- [ ] Network timeouts are handled
- [ ] Scan cancellation works
- [ ] Error messages are helpful

## Troubleshooting

### Common Issues

**Docker containers not starting:**
```bash
docker-compose down
docker-compose up -d --force-recreate
```

**Backend not connecting to database:**
```bash
# Check connection
docker-compose ps
# Reset database
docker-compose down -v
docker-compose up -d postgres
```

**Scans not starting:**
```bash
# Check Celery worker
celery -A celery_app inspect active
# Restart worker
pkill -f celery
celery -A celery_app worker --loglevel=info --pool=solo
```

**No scan results:**
```bash
# Check container images
docker images | grep -E "(nmap|zap|nuclei)"
# Pull latest images
docker pull instrumentisto/nmap:latest
docker pull ghcr.io/zaproxy/zaproxy:latest
```

### Performance Optimization

**For faster testing:**
- Use smaller port ranges (1-100 instead of 1-65535)
- Set aggressive timing (-T5) for Nmap
- Reduce spider time for ZAP (1-2 minutes)
- Limit Nuclei templates to specific categories

**For production testing:**
- Use conservative timing (-T2) for Nmap
- Increase ZAP spider time (10+ minutes)
- Enable all Nuclei templates
- Set longer scan timeouts

## Security Considerations

⚠️ **Warning:** The test web application contains intentional vulnerabilities. Only use in isolated test environments.

🔒 **Best Practices:**
- Run tests in isolated networks
- Use dedicated test infrastructure
- Monitor resource usage during scans
- Validate scan targets before execution
- Review findings before marking as false positives

## Support

If you encounter issues:

1. Check the comprehensive test output
2. Review API documentation at `/docs`
3. Examine Celery worker logs
4. Verify Docker container status
5. Test individual components separately

For additional help, check the main SecDash documentation or create an issue with:
- Test output logs
- Environment details
- Specific error messages
- Steps to reproduce
