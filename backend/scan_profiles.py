"""
Predefined scan profiles for different security tools
"""

SCAN_PROFILES = {
    "nmap": {
        "tcp_syn_scan": {
            "name": "TCP SYN Scan",
            "description": "Fast TCP SYN scan for open ports",
            "command_template": "nmap -sS -Pn {timing} -p {port_range} {target}",
            "default_options": {
                "port_range": "1-1000",
                "timing": "-T4",
                "scan_type": "tcp_syn"
            },
            "timeout_seconds": 600
        },
        "tcp_connect_scan": {
            "name": "TCP Connect Scan",
            "description": "Full TCP connect scan",
            "command_template": "nmap -sT -Pn {timing} -p {port_range} {target}",
            "default_options": {
                "port_range": "1-1000",
                "timing": "-T4",
                "scan_type": "tcp_connect"
            },
            "timeout_seconds": 900
        },
        "udp_scan": {
            "name": "UDP Scan",
            "description": "UDP port scan for common services",
            "command_template": "nmap -sU -Pn {timing} --top-ports {top_ports} {target}",
            "default_options": {
                "top_ports": "100",
                "timing": "-T4",
                "scan_type": "udp"
            },
            "timeout_seconds": 1800
        },
        "service_detection": {
            "name": "Service Version Detection",
            "description": "Detect service versions and OS",
            "command_template": "nmap -sS -sV -O -Pn {timing} -p {port_range} {target}",
            "default_options": {
                "port_range": "1-1000",
                "timing": "-T4",
                "scan_type": "service_detection",
                "enable_scripts": True
            },
            "timeout_seconds": 1200
        },
        "comprehensive": {
            "name": "Comprehensive Scan",
            "description": "Full port scan with scripts and OS detection",
            "command_template": "nmap -sS -sV -sC -O -A -Pn {timing} -p {port_range} {target}",
            "default_options": {
                "port_range": "1-65535",
                "timing": "-T4",
                "scan_type": "comprehensive",
                "enable_scripts": True,
                "os_detection": True
            },
            "timeout_seconds": 3600
        },
        "vulnerability_scan": {
            "name": "Vulnerability Scan",
            "description": "Nmap with vulnerability detection scripts",
            "command_template": "nmap -sS -sV --script vuln -Pn {timing} -p {port_range} {target}",
            "default_options": {
                "port_range": "1-1000",
                "timing": "-T4",
                "scan_type": "vulnerability_scan",
                "enable_scripts": True
            },
            "timeout_seconds": 1800
        }
    },
    "zap": {
        "baseline": {
            "name": "ZAP Baseline Scan",
            "description": "Quick baseline security scan",
            "command_template": "zap-baseline.py -t {target_url} -r {report_file}",
            "default_options": {
                "scan_type": "baseline",
                "spider_minutes": 2,
                "ajax_spider": False,
                "passive_scan": True,
                "active_scan": False
            },
            "timeout_seconds": 600
        },
        "full_scan": {
            "name": "ZAP Full Scan",
            "description": "Comprehensive web application security scan",
            "command_template": "zap-full-scan.py -t {target_url} -r {report_file}",
            "default_options": {
                "scan_type": "full",
                "spider_minutes": 5,
                "ajax_spider": True,
                "passive_scan": True,
                "active_scan": True
            },
            "timeout_seconds": 1800
        },
        "api_scan": {
            "name": "ZAP API Scan",
            "description": "API security testing",
            "command_template": "zap-api-scan.py -t {target_url} -f openapi -r {report_file}",
            "default_options": {
                "scan_type": "api",
                "api_format": "openapi",
                "passive_scan": True,
                "active_scan": True
            },
            "timeout_seconds": 900
        }
    },
    "nuclei": {
        "cve_scan": {
            "name": "CVE Scan",
            "description": "Scan for known CVEs",
            "command_template": "nuclei -u {target} -t cves/ -severity {severity} -o {output_file}",
            "default_options": {
                "templates": ["cves"],
                "severity": ["medium", "high", "critical"],
                "scan_type": "cve"
            },
            "timeout_seconds": 900
        },
        "vulnerability_scan": {
            "name": "Vulnerability Scan",
            "description": "General vulnerability templates",
            "command_template": "nuclei -u {target} -t vulnerabilities/ -severity {severity} -o {output_file}",
            "default_options": {
                "templates": ["vulnerabilities"],
                "severity": ["medium", "high", "critical"],
                "scan_type": "vulnerability"
            },
            "timeout_seconds": 600
        },
        "misconfiguration_scan": {
            "name": "Misconfiguration Scan",
            "description": "Security misconfigurations",
            "command_template": "nuclei -u {target} -t misconfigurations/ -severity {severity} -o {output_file}",
            "default_options": {
                "templates": ["misconfigurations"],
                "severity": ["info", "low", "medium", "high"],
                "scan_type": "misconfiguration"
            },
            "timeout_seconds": 300
        }
    },
    "openvas": {
        "full_and_fast": {
            "name": "Full and Fast",
            "description": "Comprehensive vulnerability assessment",
            "command_template": "gvm-cli --gmp-username {username} --gmp-password {password} tls scan create --name '{scan_name}' --target '{target}' --config '{config}'",
            "default_options": {
                "config": "daba56c8-73ec-11df-a475-002264764cea",  # Full and fast UUID
                "scan_type": "full_and_fast"
            },
            "timeout_seconds": 3600
        }
    },
    "metasploit": {
        "port_scan": {
            "name": "Port Scanner",
            "description": "Metasploit port scanning modules",
            "command_template": "msfconsole -q -x 'use auxiliary/scanner/portscan/tcp; set RHOSTS {target}; set PORTS {ports}; run; exit'",
            "default_options": {
                "ports": "1-1000",
                "scan_type": "port_scan"
            },
            "timeout_seconds": 900
        },
        "service_scan": {
            "name": "Service Scanner",
            "description": "Service detection and enumeration",
            "command_template": "msfconsole -q -x 'use auxiliary/scanner/discovery/udp_sweep; set RHOSTS {target}; run; exit'",
            "default_options": {
                "scan_type": "service_scan"
            },
            "timeout_seconds": 1200
        }
    },
    "tshark": {
        "network_capture": {
            "name": "Network Capture",
            "description": "Basic network traffic capture",
            "command_template": "tshark -i any -c {packet_count} -a duration:{duration} -w {output_file}",
            "default_options": {
                "duration": 60,
                "packet_count": 1000,
                "capture_filter": "",
                "scan_type": "network_capture"
            },
            "timeout_seconds": 120
        },
        "protocol_analysis": {
            "name": "Protocol Analysis",
            "description": "Analyze specific protocols",
            "command_template": "tshark -i any -f '{filter}' -c {packet_count} -a duration:{duration}",
            "default_options": {
                "duration": 120,
                "packet_count": 2000,
                "filter": "tcp or udp or icmp",
                "scan_type": "protocol_analysis"
            },
            "timeout_seconds": 180
        }
    },
    "nikto": {
        "web_scan": {
            "name": "Web Server Scan",
            "description": "Web server vulnerability scan",
            "command_template": "nikto -h {target} -Format json -o {output_file}",
            "default_options": {
                "scan_type": "web_scan",
                "check_outdated": True,
                "scan_cgi": True
            },
            "timeout_seconds": 900
        }
    }
}

def get_scan_profile(tool: str, profile_name: str) -> dict:
    """Get a specific scan profile"""
    return SCAN_PROFILES.get(tool, {}).get(profile_name)

def get_tool_profiles(tool: str) -> dict:
    """Get all profiles for a specific tool"""
    return SCAN_PROFILES.get(tool, {})

def list_all_profiles() -> dict:
    """List all available scan profiles"""
    return SCAN_PROFILES
