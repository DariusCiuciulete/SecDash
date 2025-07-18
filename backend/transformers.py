"""
Security scan result transformers for unified vulnerability format
"""
import re
import json
from typing import List, Dict, Any
from datetime import datetime


def nmap_to_unified(raw_output: str, scan_id: str, target: str) -> List[Dict[str, Any]]:
    """
    Transform Nmap scan results to unified vulnerability format
    """
    findings = []
    current_host = target
    
    # Remove the hardcoded mock data generation - let it parse the actual mock output
    lines = raw_output.splitlines()
    in_port_section = False
    
    for line in lines:
        line = line.strip()
        
        # Extract host information
        host_match = re.search(r"Nmap scan report for (.+)", line)
        if host_match:
            current_host = host_match.group(1).strip()
            continue
        
        # Check for port scan section
        if "PORT" in line and "STATE" in line and "SERVICE" in line:
            in_port_section = True
            continue
        
        # End of port section
        if in_port_section and (line == "" or line.startswith("Service detection") or line.startswith("Nmap done")):
            in_port_section = False
            continue
        
        # Parse port information in port section
        if in_port_section:
            # Match various nmap port output formats
            # Format: 22/tcp   open  ssh
            # Format: 80/tcp   open  http    Apache httpd 2.4.41
            # Format: 443/tcp  closed https
            port_match = re.match(r"^(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)(.*)$", line)
            if port_match:
                port = int(port_match.group(1))
                protocol = port_match.group(2)
                state = port_match.group(3)
                service = port_match.group(4)
                extra_info = port_match.group(5).strip()
                
                # Only report open ports as findings
                if state == "open":
                    # Determine severity based on port and service
                    severity = _get_port_severity(port, service)
                    
                    finding = {
                        "vuln_id": f"OPEN_PORT_{protocol.upper()}_{port}",
                        "name": f"Open {protocol.upper()} Port {port} ({service})",
                        "description": f"Open {service} service detected on port {port}/{protocol}",
                        "severity": severity,
                        "host": current_host,
                        "port": port,
                        "service": service,
                        "evidence": line,
                        "cvss_score": None,
                        "references": [],
                    }
                    
                    # Add version information if available
                    if extra_info:
                        finding["description"] += f". Version info: {extra_info}"
                    
                    findings.append(finding)
        
        # Parse standard format outside port section
        elif not in_port_section:
            # Match simple format: 22/tcp open ssh
            port_match = re.match(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)", line)
            if port_match:
                port = int(port_match.group(1))
                protocol = port_match.group(2)
                service = port_match.group(3)
                
                severity = _get_port_severity(port, service)
                
                findings.append({
                    "vuln_id": f"OPEN_PORT_{protocol.upper()}_{port}",
                    "name": f"Open {protocol.upper()} Port {port} ({service})",
                    "description": f"Open {service} service detected on port {port}/{protocol}",
                    "severity": severity,
                    "host": current_host,
                    "port": port,
                    "service": service,
                    "evidence": line,
                    "cvss_score": None,
                    "references": [],
                })
        
        # Parse Nmap script results for vulnerabilities
        script_match = re.match(r"^\|\s+(.+):\s+VULNERABLE", line)
        if script_match:
            vuln_name = script_match.group(1)
            findings.append({
                "vuln_id": f"NSE_{vuln_name.replace(' ', '_').upper()}",
                "name": vuln_name,
                "description": f"Vulnerability detected by Nmap script: {vuln_name}",
                "severity": "medium",
                "host": current_host,
                "port": None,
                "service": None,
                "evidence": line,
                "cvss_score": None,
                "references": [],
            })
        
        # Parse CVE references
        cve_match = re.search(r"(CVE-\d{4}-\d+)", line)
        if cve_match and findings:
            cve_id = cve_match.group(1)
            findings[-1]["vuln_id"] = cve_id
            findings[-1]["severity"] = "high"  # Assume high for CVEs
    
    return findings


def _get_port_severity(port: int, service: str) -> str:
    """
    Determine severity level for open ports based on port number and service
    """
    # Common dangerous services
    high_risk_services = ["telnet", "ftp", "tftp", "snmp", "rlogin", "rsh", "finger"]
    high_risk_ports = [21, 23, 69, 161, 512, 513, 514, 515, 79]
    
    # Management/Admin services
    medium_risk_services = ["ssh", "rdp", "vnc", "winrm", "mysql", "postgresql", "mssql", "mongodb"]
    medium_risk_ports = [22, 3389, 5900, 5985, 5986, 3306, 5432, 1433, 27017]
    
    # Low risk but notable services  
    low_risk_services = ["http", "https", "smtp", "pop3", "imap", "dns"]
    low_risk_ports = [80, 443, 25, 110, 143, 53]
    
    if service.lower() in high_risk_services or port in high_risk_ports:
        return "high"
    elif service.lower() in medium_risk_services or port in medium_risk_ports:
        return "medium"
    elif service.lower() in low_risk_services or port in low_risk_ports:
        return "low"
    else:
        return "info"


def zap_to_unified(raw_output: str, scan_id: str, target: str) -> List[Dict[str, Any]]:
    """
    Transform OWASP ZAP scan results to unified vulnerability format
    """
    findings = []
    
    try:
        # Try to parse JSON output first
        if raw_output.strip().startswith('{'):
            zap_data = json.loads(raw_output)
            site = zap_data.get("site", [{}])[0]
            alerts = site.get("alerts", [])
            
            for alert in alerts:
                risk_level = alert.get("riskdesc", "").lower()
                severity = _map_zap_risk_to_severity(risk_level)
                
                # Parse instances for multiple occurrences
                instances = alert.get("instances", [])
                if not instances:
                    instances = [{"uri": alert.get("url", target), "evidence": alert.get("evidence", "")}]
                
                for instance in instances:
                    finding = {
                        "vuln_id": f"ZAP_{alert.get('pluginid', 'UNKNOWN')}",
                        "name": alert.get("name", "Unknown Vulnerability"),
                        "description": alert.get("desc", ""),
                        "severity": severity,
                        "host": target,
                        "port": _extract_port_from_url(instance.get("uri", target)),
                        "service": "HTTP",
                        "path": instance.get("uri", ""),
                        "evidence": instance.get("evidence", ""),
                        "impact": alert.get("impact", ""),
                        "recommendation": alert.get("solution", ""),
                        "cvss_score": _parse_cvss_from_zap(alert.get("riskdesc", "")),
                        "references": alert.get("reference", "").split("\n") if alert.get("reference") else [],
                        "cwe": alert.get("cweid"),
                        "wasc": alert.get("wascid"),
                        "attack": alert.get("attack", ""),
                        "param": instance.get("param", ""),
                        "method": instance.get("method", "GET"),
                    }
                    findings.append(finding)
        
        else:
            # Parse text output as fallback
            lines = raw_output.splitlines()
            current_finding = None
            
            for line in lines:
                line = line.strip()
                
                # Look for different ZAP output patterns
                if "FAIL" in line or "WARN" in line or "INFO" in line:
                    severity = "high" if "FAIL" in line else ("medium" if "WARN" in line else "info")
                    
                    finding = {
                        "vuln_id": "ZAP_BASELINE_FINDING",
                        "name": "ZAP Baseline Finding",
                        "description": line,
                        "severity": severity,
                        "host": target,
                        "port": None,
                        "service": "HTTP",
                        "evidence": line,
                        "cvss_score": None,
                        "references": [],
                    }
                    findings.append(finding)
                
                # Parse alert start
                elif line.startswith("Alert:"):
                    if current_finding:
                        findings.append(current_finding)
                    current_finding = {
                        "vuln_id": "ZAP_ALERT",
                        "name": line.replace("Alert:", "").strip(),
                        "description": "",
                        "severity": "medium",
                        "host": target,
                        "port": None,
                        "service": "HTTP",
                        "evidence": "",
                        "cvss_score": None,
                        "references": [],
                    }
                
                # Parse other alert details
                elif current_finding:
                    if line.startswith("Risk:"):
                        risk = line.replace("Risk:", "").strip().lower()
                        current_finding["severity"] = _map_zap_risk_to_severity(risk)
                    elif line.startswith("Description:"):
                        current_finding["description"] = line.replace("Description:", "").strip()
                    elif line.startswith("URL:"):
                        url = line.replace("URL:", "").strip()
                        current_finding["path"] = url
                        current_finding["port"] = _extract_port_from_url(url)
            
            # Add last finding
            if current_finding:
                findings.append(current_finding)
    
    except json.JSONDecodeError:
        # If JSON parsing fails, try to extract basic info from text
        lines = raw_output.splitlines()
        for line in lines:
            if any(keyword in line.lower() for keyword in ["vulnerability", "risk", "alert", "warning"]):
                findings.append({
                    "vuln_id": "ZAP_TEXT_FINDING",
                    "name": "ZAP Text Finding",
                    "description": line.strip(),
                    "severity": "medium",
                    "host": target,
                    "port": None,
                    "service": "HTTP",
                    "evidence": line.strip(),
                    "cvss_score": None,
                    "references": [],
                })
    
    return findings


def nuclei_to_unified(raw_output: str, scan_id: str, target: str) -> List[Dict[str, Any]]:
    """
    Transform Nuclei scan results to unified vulnerability format
    """
    findings = []
    
    try:
        # Nuclei outputs JSON lines format
        lines = raw_output.strip().splitlines()
        
        for line in lines:
            if line.strip() and line.startswith('{'):
                try:
                    nuclei_finding = json.loads(line)
                    
                    # Extract information from Nuclei JSON
                    template_id = nuclei_finding.get("template-id", "unknown")
                    template_name = nuclei_finding.get("info", {}).get("name", "Unknown")
                    severity = nuclei_finding.get("info", {}).get("severity", "info").lower()
                    description = nuclei_finding.get("info", {}).get("description", "")
                    matched_at = nuclei_finding.get("matched-at", target)
                    
                    # Parse tags for additional context
                    tags = nuclei_finding.get("info", {}).get("tags", [])
                    if isinstance(tags, str):
                        tags = tags.split(",")
                    
                    # Parse classification
                    classification = nuclei_finding.get("info", {}).get("classification", {})
                    cve_id = classification.get("cve-id")
                    cwe_id = classification.get("cwe-id")
                    cvss_score = classification.get("cvss-score")
                    
                    finding = {
                        "vuln_id": f"NUCLEI_{template_id}",
                        "name": template_name,
                        "description": description,
                        "severity": _map_nuclei_severity(severity),
                        "host": _extract_host_from_url(matched_at),
                        "port": _extract_port_from_url(matched_at),
                        "service": _extract_service_from_url(matched_at),
                        "path": matched_at,
                        "evidence": nuclei_finding.get("matched-at", ""),
                        "cvss_score": cvss_score,
                        "references": nuclei_finding.get("info", {}).get("reference", []),
                        "cve": cve_id,
                        "cwe": cwe_id,
                        "tags": tags,
                        "template_id": template_id,
                        "template_path": nuclei_finding.get("template-path", ""),
                        "matcher_name": nuclei_finding.get("matcher-name", ""),
                        "type": nuclei_finding.get("type", ""),
                    }
                    
                    findings.append(finding)
                    
                except json.JSONDecodeError:
                    continue
    
    except Exception as e:
        # Fallback to basic text parsing
        lines = raw_output.splitlines()
        for line in lines:
            if "[" in line and "]" in line and any(severity in line.lower() for severity in ["critical", "high", "medium", "low", "info"]):
                findings.append({
                    "vuln_id": "NUCLEI_TEXT_FINDING",
                    "name": "Nuclei Finding",
                    "description": line.strip(),
                    "severity": "medium",
                    "host": target,
                    "port": None,
                    "service": "Unknown",
                    "evidence": line.strip(),
                    "cvss_score": None,
                    "references": [],
                })
    
    return findings


def metasploit_to_unified(raw_output: str, scan_id: str, target: str) -> List[Dict[str, Any]]:
    """
    Transform Metasploit scan results to unified vulnerability format
    """
    findings = []
    
    lines = raw_output.splitlines()
    current_host = target
    
    for line in lines:
        line = line.strip()
        
        # Parse host information
        if "Discovered open port" in line or "open" in line.lower():
            # Extract port information from various Metasploit output formats
            port_match = re.search(r"(\d+)/(tcp|udp)", line)
            if port_match:
                port = int(port_match.group(1))
                protocol = port_match.group(2)
                
                finding = {
                    "vuln_id": f"MSF_OPEN_PORT_{protocol.upper()}_{port}",
                    "name": f"Open {protocol.upper()} Port {port}",
                    "description": f"Metasploit discovered open port {port}/{protocol}",
                    "severity": _get_port_severity(port, "unknown"),
                    "host": current_host,
                    "port": port,
                    "service": _get_service_by_port(port),
                    "evidence": line,
                    "cvss_score": None,
                    "references": [],
                    "tool": "metasploit",
                }
                findings.append(finding)
        
        # Parse service detection
        elif "appears to be" in line or "running" in line:
            service_match = re.search(r"(\d+)/(tcp|udp).*?(\w+)", line)
            if service_match:
                port = int(service_match.group(1))
                protocol = service_match.group(2)
                service = service_match.group(3)
                
                finding = {
                    "vuln_id": f"MSF_SERVICE_{protocol.upper()}_{port}_{service.upper()}",
                    "name": f"Service Detection: {service}",
                    "description": f"Metasploit detected {service} service on port {port}/{protocol}",
                    "severity": "info",
                    "host": current_host,
                    "port": port,
                    "service": service,
                    "evidence": line,
                    "cvss_score": None,
                    "references": [],
                    "tool": "metasploit",
                }
                findings.append(finding)
        
        # Parse vulnerability findings
        elif "vulnerable" in line.lower() or "exploit" in line.lower():
            finding = {
                "vuln_id": "MSF_VULNERABILITY",
                "name": "Metasploit Vulnerability Finding",
                "description": line,
                "severity": "high",
                "host": current_host,
                "port": None,
                "service": "Unknown",
                "evidence": line,
                "cvss_score": None,
                "references": [],
                "tool": "metasploit",
            }
            findings.append(finding)
    
    return findings


def tshark_to_unified(raw_output: str, scan_id: str, target: str) -> List[Dict[str, Any]]:
    """
    Transform Tshark/Wireshark capture results to unified vulnerability format
    """
    findings = []
    
    try:
        # Try to parse JSON output
        if raw_output.strip().startswith('['):
            packets = json.loads(raw_output)
            
            protocol_counts = {}
            suspicious_patterns = []
            
            for packet in packets:
                layers = packet.get("_source", {}).get("layers", {})
                
                # Analyze protocols
                for protocol in layers.keys():
                    protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
                
                # Look for suspicious patterns
                if "tcp" in layers:
                    tcp_layer = layers["tcp"]
                    flags = tcp_layer.get("tcp.flags", "")
                    if "syn" in flags and "ack" not in flags:
                        suspicious_patterns.append("SYN_SCAN")
                
                if "icmp" in layers:
                    suspicious_patterns.append("ICMP_TRAFFIC")
                
                # Check for unusual ports
                if "tcp" in layers:
                    dst_port = layers["tcp"].get("tcp.dstport")
                    if dst_port and int(dst_port) > 49152:  # Dynamic/private ports
                        suspicious_patterns.append(f"HIGH_PORT_{dst_port}")
            
            # Create findings from analysis
            for protocol, count in protocol_counts.items():
                if count > 100:  # High volume traffic
                    finding = {
                        "vuln_id": f"TSHARK_HIGH_VOLUME_{protocol.upper()}",
                        "name": f"High Volume {protocol.upper()} Traffic",
                        "description": f"Detected {count} {protocol} packets, possibly indicating scanning or DoS",
                        "severity": "medium",
                        "host": target,
                        "port": None,
                        "service": protocol,
                        "evidence": f"{count} packets detected",
                        "cvss_score": None,
                        "references": [],
                        "tool": "tshark",
                    }
                    findings.append(finding)
            
            # Add suspicious pattern findings
            for pattern in set(suspicious_patterns):
                severity = "high" if "SCAN" in pattern else "medium"
                finding = {
                    "vuln_id": f"TSHARK_{pattern}",
                    "name": f"Suspicious Pattern: {pattern}",
                    "description": f"Tshark detected suspicious network pattern: {pattern}",
                    "severity": severity,
                    "host": target,
                    "port": None,
                    "service": "Network",
                    "evidence": pattern,
                    "cvss_score": None,
                    "references": [],
                    "tool": "tshark",
                }
                findings.append(finding)
        
        else:
            # Parse text output
            lines = raw_output.splitlines()
            for line in lines:
                if any(keyword in line.lower() for keyword in ["syn", "rst", "fin", "ack"]):
                    finding = {
                        "vuln_id": "TSHARK_NETWORK_ACTIVITY",
                        "name": "Network Activity",
                        "description": f"Network activity detected: {line}",
                        "severity": "info",
                        "host": target,
                        "port": None,
                        "service": "Network",
                        "evidence": line,
                        "cvss_score": None,
                        "references": [],
                        "tool": "tshark",
                    }
                    findings.append(finding)
    
    except Exception as e:
        # Basic fallback
        if raw_output.strip():
            finding = {
                "vuln_id": "TSHARK_CAPTURE",
                "name": "Network Capture Analysis",
                "description": "Tshark network capture completed",
                "severity": "info",
                "host": target,
                "port": None,
                "service": "Network",
                "evidence": "Network capture data available",
                "cvss_score": None,
                "references": [],
                "tool": "tshark",
            }
            findings.append(finding)
    
    return findings


def openvas_to_unified(raw_output: str, scan_id: str, target: str) -> List[Dict[str, Any]]:
    """
    Transform OpenVAS scan results to unified vulnerability format
    """
    findings = []
    
    try:
        # Try to parse XML output (OpenVAS typically outputs XML)
        if raw_output.strip().startswith('<'):
            import xml.etree.ElementTree as ET
            root = ET.fromstring(raw_output)
            
            # Parse results from OpenVAS XML format
            for result in root.findall(".//result"):
                nvt = result.find("nvt")
                if nvt is not None:
                    oid = nvt.get("oid", "")
                    name = nvt.find("name").text if nvt.find("name") is not None else "Unknown"
                    
                    severity_elem = result.find("severity")
                    severity_score = float(severity_elem.text) if severity_elem is not None else 0.0
                    severity = _map_openvas_severity(severity_score)
                    
                    description_elem = result.find("description")
                    description = description_elem.text if description_elem is not None else ""
                    
                    host_elem = result.find("host")
                    host = host_elem.text if host_elem is not None else target
                    
                    port_elem = result.find("port")
                    port = None
                    service = "Unknown"
                    if port_elem is not None:
                        port_text = port_elem.text
                        if "/" in port_text:
                            port_num, service = port_text.split("/", 1)
                            try:
                                port = int(port_num)
                            except ValueError:
                                pass
                    
                    finding = {
                        "vuln_id": f"OPENVAS_{oid}",
                        "name": name,
                        "description": description,
                        "severity": severity,
                        "host": host,
                        "port": port,
                        "service": service,
                        "evidence": description,
                        "cvss_score": severity_score if severity_score > 0 else None,
                        "references": [],
                        "oid": oid,
                        "tool": "openvas",
                    }
                    findings.append(finding)
        
        else:
            # Parse text output as fallback
            lines = raw_output.splitlines()
            for line in lines:
                if any(keyword in line.lower() for keyword in ["vulnerability", "security", "risk", "cve"]):
                    finding = {
                        "vuln_id": "OPENVAS_TEXT_FINDING",
                        "name": "OpenVAS Finding",
                        "description": line.strip(),
                        "severity": "medium",
                        "host": target,
                        "port": None,
                        "service": "Unknown",
                        "evidence": line.strip(),
                        "cvss_score": None,
                        "references": [],
                        "tool": "openvas",
                    }
                    findings.append(finding)
    
    except Exception as e:
        # Basic fallback
        if raw_output.strip():
            finding = {
                "vuln_id": "OPENVAS_SCAN_RESULT",
                "name": "OpenVAS Scan Completed",
                "description": "OpenVAS vulnerability scan completed",
                "severity": "info",
                "host": target,
                "port": None,
                "service": "Unknown",
                "evidence": "Scan completed successfully",
                "cvss_score": None,
                "references": [],
                "tool": "openvas",
            }
            findings.append(finding)
    
    return findings


def _extract_port_from_url(url: str) -> int:
    """Extract port number from URL"""
    import re
    from urllib.parse import urlparse
    
    try:
        parsed = urlparse(url)
        if parsed.port:
            return parsed.port
        
        # Default ports for common schemes
        if parsed.scheme == "https":
            return 443
        elif parsed.scheme == "http":
            return 80
        elif parsed.scheme == "ftp":
            return 21
        elif parsed.scheme == "ssh":
            return 22
        
        # Try to extract port from string patterns
        port_match = re.search(r":(\d+)", url)
        if port_match:
            return int(port_match.group(1))
            
    except Exception:
        pass
    
    return None


def _extract_host_from_url(url: str) -> str:
    """Extract hostname from URL"""
    from urllib.parse import urlparse
    
    try:
        parsed = urlparse(url)
        if parsed.hostname:
            return parsed.hostname
        
        # Fallback for non-standard URLs
        if "://" in url:
            url = url.split("://", 1)[1]
        if "/" in url:
            url = url.split("/", 1)[0]
        if ":" in url:
            url = url.split(":", 1)[0]
        
        return url
    except Exception:
        return url


def _extract_service_from_url(url: str) -> str:
    """Extract service name from URL"""
    from urllib.parse import urlparse
    
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        
        if scheme in ["http", "https"]:
            return "HTTP"
        elif scheme == "ftp":
            return "FTP"
        elif scheme == "ssh":
            return "SSH"
        else:
            return scheme.upper() if scheme else "Unknown"
    except Exception:
        return "Unknown"


def nikto_to_unified(raw_output: str, scan_id: str, target: str) -> List[Dict[str, Any]]:
    """
    Transform Nikto scan results to unified vulnerability format
    """
    findings = []
    
    try:
        # Try to parse JSON output first
        if raw_output.strip().startswith('{'):
            nikto_data = json.loads(raw_output)
            
            vulnerabilities = nikto_data.get("vulnerabilities", [])
            for vuln in vulnerabilities:
                finding = {
                    "vuln_id": f"NIKTO_{vuln.get('id', 'UNKNOWN')}",
                    "name": vuln.get("msg", "Nikto Finding"),
                    "description": vuln.get("msg", ""),
                    "severity": _map_nikto_severity(vuln.get("OSVDB", "")),
                    "host": target,
                    "port": _extract_port_from_url(vuln.get("uri", target)),
                    "service": "HTTP",
                    "path": vuln.get("uri", ""),
                    "evidence": vuln.get("msg", ""),
                    "cvss_score": None,
                    "references": [vuln.get("OSVDB", "")] if vuln.get("OSVDB") else [],
                    "tool": "nikto",
                }
                findings.append(finding)
        
        else:
            # Parse text output
            lines = raw_output.splitlines()
            current_target = target
            
            for line in lines:
                line = line.strip()
                
                # Parse target information
                if "Testing:" in line:
                    target_match = re.search(r"Testing:\s+(.+)", line)
                    if target_match:
                        current_target = target_match.group(1)
                
                # Parse vulnerabilities (+ indicates finding)
                elif line.startswith("+"):
                    # Remove the + prefix and parse
                    vuln_text = line[1:].strip()
                    
                    # Extract OSVDB reference if present
                    osvdb_match = re.search(r"OSVDB-(\d+)", vuln_text)
                    osvdb_id = osvdb_match.group(1) if osvdb_match else ""
                    
                    # Determine severity based on keywords
                    severity = "medium"
                    if any(keyword in vuln_text.lower() for keyword in ["critical", "high", "dangerous"]):
                        severity = "high"
                    elif any(keyword in vuln_text.lower() for keyword in ["low", "info", "disclosed"]):
                        severity = "low"
                    
                    finding = {
                        "vuln_id": f"NIKTO_OSVDB_{osvdb_id}" if osvdb_id else "NIKTO_FINDING",
                        "name": "Nikto Web Server Finding",
                        "description": vuln_text,
                        "severity": severity,
                        "host": current_target,
                        "port": _extract_port_from_url(current_target),
                        "service": "HTTP",
                        "path": current_target,
                        "evidence": vuln_text,
                        "cvss_score": None,
                        "references": [f"OSVDB-{osvdb_id}"] if osvdb_id else [],
                        "tool": "nikto",
                    }
                    findings.append(finding)
    
    except Exception as e:
        # Fallback for any parsing errors
        if raw_output.strip():
            finding = {
                "vuln_id": "NIKTO_SCAN_RESULT",
                "name": "Nikto Scan Completed",
                "description": "Nikto web server scan completed",
                "severity": "info",
                "host": target,
                "port": None,
                "service": "HTTP",
                "evidence": "Scan completed successfully",
                "cvss_score": None,
                "references": [],
                "tool": "nikto",
            }
            findings.append(finding)
    
    return findings


def _map_nikto_severity(osvdb: str) -> str:
    """Map Nikto OSVDB references to severity levels"""
    if not osvdb:
        return "medium"
    
    # High-risk OSVDB ranges (this is a simplified mapping)
    osvdb_num = re.search(r"(\d+)", osvdb)
    if osvdb_num:
        num = int(osvdb_num.group(1))
        if num < 1000:  # Older, potentially more serious issues
            return "high"
        elif num < 10000:
            return "medium"
        else:
            return "low"
    
    return "medium"


def _parse_cvss_from_zap(risk_desc: str) -> float:
    """Parse CVSS score from ZAP risk description"""
    import re
    
    try:
        # Look for CVSS score patterns
        cvss_match = re.search(r"cvss[:\s]*(\d+\.?\d*)", risk_desc.lower())
        if cvss_match:
            return float(cvss_match.group(1))
        
        # Map risk levels to approximate CVSS scores
        risk_lower = risk_desc.lower()
        if "high" in risk_lower:
            return 7.5
        elif "medium" in risk_lower:
            return 5.0
        elif "low" in risk_lower:
            return 2.5
        elif "informational" in risk_lower:
            return 0.0
            
    except Exception:
        pass
    
    return None


def _map_nuclei_severity(severity: str) -> str:
    """Map Nuclei severity to standard levels"""
    mapping = {
        "critical": "critical",
        "high": "high", 
        "medium": "medium",
        "low": "low",
        "info": "info",
        "informational": "info",
        "unknown": "info"
    }
    return mapping.get(severity.lower(), "info")


def _get_service_by_port(port: int) -> str:
    """Get common service name by port number"""
    common_ports = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        135: "RPC",
        139: "NetBIOS",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        993: "IMAPS",
        995: "POP3S",
        1433: "MSSQL",
        1521: "Oracle",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        6379: "Redis",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt",
        27017: "MongoDB"
    }
    return common_ports.get(port, "Unknown")


def _map_openvas_severity(score: float) -> str:
    """Map OpenVAS CVSS score to severity level"""
    if score >= 9.0:
        return "critical"
    elif score >= 7.0:
        return "high"
    elif score >= 4.0:
        return "medium"
    elif score > 0.0:
        return "low"
    else:
        return "info"


def _map_zap_risk_to_severity(risk_level: str) -> str:
    """Map ZAP risk level to standard severity"""
    risk_mapping = {
        "high": "high",
        "medium": "medium", 
        "low": "low",
        "informational": "info",
    }
    return risk_mapping.get(risk_level, "info")


def _map_openvas_threat_to_severity(threat: str) -> str:
    """Map OpenVAS threat level to standard severity"""
    threat_mapping = {
        "high": "high",
        "medium": "medium",
        "low": "low",
        "log": "info",
        "debug": "info",
    }
    return threat_mapping.get(threat, "info")


def _normalize_severity(severity: str) -> str:
    """Normalize severity values"""
    severity = severity.lower()
    if severity in ["critical", "high", "medium", "low", "info"]:
        return severity
    elif severity in ["informational", "information"]:
        return "info"
    else:
        return "info"