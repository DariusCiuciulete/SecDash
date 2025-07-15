# All scan outputs are transformed into this schema for storage and reporting:


unified_scan_schema = {
    "scan_id": "string",                 # Unique scan identifier (UUID or similar)
    "tool": "string",                    # Tool used (e.g., "nmap", "zap", "metasploit", "tshark")
    "profile": "string",                 # Scan profile name or ID
    "targets": ["string"],               # List of scanned targets (IP, hostname)
    "status": "string",                  # Scan status ("queued", "running", "complete", "error")
    "start_time": "string",              # ISO8601 datetime of scan start
    "end_time": "string",                # ISO8601 datetime of scan completion
    "duration_seconds": "number",        # (optional) Time taken
    "findings": [                        # List of findings (deduplicated)
        {
            "finding_id": "string",      # SHA-256 hash for deduplication (CVE+host+port)
            "host": "string",            # Target host/IP where finding applies
            "port": "integer",           # Port number (if applicable)
            "protocol": "string",        # Protocol ("tcp", "udp", "http", etc.)
            "service": "string",         # Service name ("http", "ssh", etc.)
            "cve": "string",             # CVE or other vuln ID (if available)
            "title": "string",           # Human-readable vuln title
            "description": "string",     # Detailed description of finding
            "severity": "string",        # Severity ("critical", "high", "medium", "low", "info")
            "evidence": "string",        # (optional) Evidence or raw output reference
            "timestamp": "string",       # (optional) When the finding was observed
        }
    ],
    "pcap_file": "string",               # Path or link to PCAP file (if generated)
    "raw_output_file": "string",         # Path or link to raw tool output
    "error": "string",                   # (optional) Error message if scan failed
    "meta": {                            # (optional) Extra data, tool-specific
        "nmap_args": "string",
        "zap_session": "string",
        "metasploit_module": "string",
        "etc": "string"
    }
}
