"""
Test the target validation improvements directly
"""

def validate_target_for_tool(tool: str, target: str) -> str:
    """Validate and format target for specific tool requirements"""
    import re
    from urllib.parse import urlparse
    
    if tool == "zap":
        # ZAP requires HTTP/HTTPS URLs
        if not target.startswith(('http://', 'https://')):
            # Try to determine if it's a web target
            if target.lower() in ['scanme.nmap.org', 'localhost', '127.0.0.1']:
                return f"http://{target}"
            else:
                # Default to HTTP for unknown targets
                return f"http://{target}"
        return target
        
    elif tool == "nuclei":
        # Nuclei can work with URLs or IPs, but prefers URLs for web scans
        if not target.startswith(('http://', 'https://')):
            # Common web targets should use HTTP
            if target.lower() in ['scanme.nmap.org', 'localhost', '127.0.0.1'] or ':' in target:
                return f"http://{target}"
        return target
        
    elif tool == "nikto":
        # Nikto is for web servers, needs HTTP/HTTPS or will assume HTTP
        if not target.startswith(('http://', 'https://')):
            return f"http://{target}"
        return target
        
    elif tool in ["nmap", "metasploit", "openvas"]:
        # These tools work with IPs/hostnames directly
        # Remove protocol if present
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            target = parsed.netloc
            if ':' in target and not re.match(r'.*:\d+$', target):
                # Remove port if it's not just digits
                target = target.split(':')[0]
        return target
        
    elif tool == "tshark":
        # Tshark doesn't target specific hosts, it captures network traffic
        # For testing, we'll just return the target as-is
        return target
        
    else:
        return target

def test_target_validation():
    """Test the target validation function"""
    print("=== Target Validation Test ===\n")
    
    test_cases = [
        # (tool, input_target, expected_output)
        ("nmap", "scanme.nmap.org", "scanme.nmap.org"),
        ("nmap", "http://scanme.nmap.org", "scanme.nmap.org"),
        ("nmap", "https://example.com:8080", "example.com"),
        
        ("zap", "scanme.nmap.org", "http://scanme.nmap.org"),
        ("zap", "http://scanme.nmap.org", "http://scanme.nmap.org"),
        ("zap", "unknown-site.com", "http://unknown-site.com"),
        
        ("nuclei", "scanme.nmap.org", "http://scanme.nmap.org"),
        ("nuclei", "http://example.com", "http://example.com"),
        ("nuclei", "192.168.1.1:8080", "http://192.168.1.1:8080"),
        
        ("nikto", "scanme.nmap.org", "http://scanme.nmap.org"),
        ("nikto", "https://secure-site.com", "https://secure-site.com"),
        
        ("metasploit", "scanme.nmap.org", "scanme.nmap.org"),
        ("metasploit", "http://scanme.nmap.org", "scanme.nmap.org"),
        
        ("tshark", "any-target", "any-target"),
    ]
    
    for tool, input_target, expected in test_cases:
        result = validate_target_for_tool(tool, input_target)
        status = "✅ PASS" if result == expected else "❌ FAIL"
        print(f"{status} {tool:12} | {input_target:25} → {result:25} (expected: {expected})")
    
    print("\n=== Key Improvements ===")
    print("1. ZAP now automatically gets HTTP URLs for web scanning")
    print("2. Nmap strips protocols to get clean hostnames")
    print("3. Nuclei intelligently converts targets to URLs when needed")
    print("4. Nikto ensures all targets are web URLs")
    print("5. Each tool gets the target format it expects")

if __name__ == "__main__":
    test_target_validation()
