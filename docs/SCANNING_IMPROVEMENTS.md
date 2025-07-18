# Scanning Functionality Improvements

## Overview
The scanning functionality has been significantly improved to provide detailed error messages instead of generic "failed" responses. This document outlines the changes made and how they address the original issues.

## Problems Identified

1. **Target Format Issues**: Different scanning tools require different target formats:
   - ZAP and Nikto need HTTP/HTTPS URLs
   - Nmap, Metasploit, and OpenVAS work with hostnames/IPs
   - Nuclei can work with both but prefers URLs for web scans

2. **Generic Error Messages**: Previous implementation returned simple "failed" messages without specific reasons

3. **Docker Dependencies**: Many tools require Docker but error handling didn't explain Docker-specific issues

4. **Network Connectivity**: Tools failed silently on network issues without explaining the root cause

## Improvements Made

### 1. Target Validation (`_validate_target_for_tool`)

Added intelligent target format validation and conversion:

```python
def _validate_target_for_tool(self, tool: str, target: str) -> str:
    """Validate and format target for specific tool requirements"""
```

**Features:**
- **ZAP/Nikto**: Automatically converts bare hostnames to HTTP URLs
- **Nmap/Metasploit/OpenVAS**: Strips protocol prefixes to get clean hostnames/IPs
- **Nuclei**: Intelligently determines if URL format is needed
- **Tshark**: Passes targets through (doesn't target specific hosts)

**Example Conversions:**
- `scanme.nmap.org` → `http://scanme.nmap.org` (for ZAP)
- `http://scanme.nmap.org` → `scanme.nmap.org` (for Nmap)

### 2. Enhanced Error Handling

Each scanning method now provides specific error messages:

#### Nmap Improvements
```python
# Before
raise RuntimeError(f"Native nmap failed: {stderr.decode('utf-8')}")

# After  
error_detail = stderr.decode('utf-8') if stderr else "Unknown error"
raise RuntimeError(f"Native nmap failed (exit code {process.returncode}): {error_detail}")
```

#### ZAP Improvements
```python
# Connection-specific errors
if "Connection refused" in logs:
    raise RuntimeError(f"ZAP could not connect to target {target}. Target may be unreachable or not running a web server.")
elif "No such host" in logs or "could not resolve" in logs:
    raise RuntimeError(f"ZAP could not resolve hostname in {target}. Check target URL validity.")
```

#### Nuclei Improvements
```python
# Network and format-specific errors
if "could not resolve" in logs.lower():
    raise RuntimeError(f"Nuclei could not resolve target {target}. Check target validity.")
elif "connection refused" in logs.lower():
    raise RuntimeError(f"Nuclei could not connect to target {target}. Target may be unreachable.")
```

#### Metasploit Improvements
```python
# Database and connectivity errors
if "could not resolve" in logs.lower():
    raise RuntimeError(f"Metasploit could not resolve target {target}. Check target validity.")
elif "Error" in logs and "database" in logs.lower():
    raise RuntimeError(f"Metasploit database error. This is likely a container configuration issue.")
```

#### Nikto Improvements
```python
# Web server specific errors
if "no web server found" in logs.lower():
    raise RuntimeError(f"Nikto found no web server at {target}. Check if target is running a web service.")
elif "connection refused" in logs.lower():
    raise RuntimeError(f"Nikto could not connect to {target}. Web server may not be running.")
```

#### Tshark Improvements
```python
# Network capture specific errors
if "permission denied" in logs.lower():
    raise RuntimeError(f"Tshark permission denied. Container needs NET_ADMIN capability for packet capture.")
elif "no such device" in logs.lower():
    raise RuntimeError(f"Tshark could not find network interface. Check Docker network configuration.")
```

### 3. Docker Availability Checks

Added explicit Docker availability checking:

```python
try:
    import docker
    docker_client = docker.from_env()
    docker_client.ping()
except Exception as docker_error:
    raise RuntimeError(f"Docker unavailable for {tool} scan: {docker_error}. {tool} requires Docker to run.")
```

### 4. Timeout Handling

Improved timeout error messages:

```python
except asyncio.TimeoutError:
    raise RuntimeError(f"Nmap scan timed out after {settings.scanners.scan_timeout} seconds")
```

### 5. OpenVAS Realistic Messaging

OpenVAS integration now provides honest feedback about complexity:

```python
raise RuntimeError(f"OpenVAS integration requires a full GVM (Greenbone Vulnerability Management) stack setup. "
                  f"This includes gvmd, redis, postgresql, and other components. "
                  f"Consider using the standalone OpenVAS VM or a proper GVM installation.")
```

## Error Message Categories

The improved error handling now provides specific messages for:

1. **Network Issues**
   - DNS resolution failures
   - Connection refused
   - Timeouts
   - Host unreachable

2. **Target Format Issues**
   - Invalid URLs
   - Missing protocols
   - Incorrect target types

3. **Docker Issues**
   - Docker daemon not running
   - Missing images
   - Container permission issues

4. **Tool-Specific Issues**
   - Web server not found (Nikto/ZAP)
   - Database errors (Metasploit)
   - Capture permissions (Tshark)
   - Complex setup requirements (OpenVAS)

## Testing the Improvements

Use the new test script to verify improvements:

```bash
python test_improved_scanning.py
```

This script tests:
- Valid targets (should succeed)
- Invalid hostnames (should show DNS errors)
- Wrong target formats (should show format errors)
- Docker dependencies (should show Docker errors)

## Example Error Messages

### Before (Generic)
```
Scan failed
ZAP scan failed
Nuclei scan failed with exit code 1
```

### After (Specific)
```
ZAP could not connect to target http://nonexistent-site.invalid. Target may be unreachable or not running a web server.

Nuclei could not resolve target nonexistent-host.invalid. Check target validity.

Docker unavailable for Metasploit scan: Cannot connect to the Docker daemon. Metasploit requires Docker to run.

Tshark permission denied. Container needs NET_ADMIN capability for packet capture.
```

## Benefits

1. **Easier Debugging**: Users can immediately understand what went wrong
2. **Better User Experience**: Clear guidance on how to fix issues
3. **Reduced Support Load**: Self-explanatory error messages
4. **Tool Education**: Users learn about tool requirements and limitations

## Future Enhancements

1. **Recovery Suggestions**: Include specific steps to fix each error type
2. **Alternative Tool Suggestions**: Suggest different tools when one fails
3. **Pre-flight Checks**: Validate environment before starting scans
4. **Error Categorization**: Group errors by type for better reporting
