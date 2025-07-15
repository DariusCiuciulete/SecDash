# backend/transformers.py

import re

def nmap_to_unified(raw_output, scan_id, target):
    findings = []
    for line in raw_output.splitlines():
        # Simple example: Look for open ports
        match = re.match(r"^(\d+)/tcp\s+open\s+(\S+)", line)
        if match:
            port = int(match.group(1))
            service = match.group(2)
            findings.append({
                "host": target,
                "port": port,
                "service": service,
                "vuln_id": "",      # Nmap itself doesn't report CVEs, but plugins might
                "vuln_name": "",
                "severity": "info",
                "description": "Open port detected",
                "evidence": line,
            })
    return {
        "scan_id": scan_id,
        "target": target,
        "start_time": "",   # fill in actual time in future steps
        "end_time": "",
        "tool": "nmap",
        "findings": findings
    }


def zap_to_unified(raw_output, scan_id, target):
    # Implement ZAP parsing here later
    return {...}