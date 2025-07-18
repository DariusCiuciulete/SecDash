"""
Simple demonstration of improved scanning error handling
"""
import requests
import time

BASE_URL = "http://localhost:8000/api/v1"

def create_test_asset(name, target, asset_type="host"):
    """Create a test asset"""
    asset_data = {
        "name": name,
        "type": asset_type,
        "target": target,
        "description": f"Test asset for {name}"
    }
    
    response = requests.post(f"{BASE_URL}/assets/", json=asset_data)
    if response.status_code == 201:
        return response.json()
    elif response.status_code == 409:  # Asset already exists
        # Get existing asset
        response = requests.get(f"{BASE_URL}/assets/")
        if response.status_code == 200:
            assets = response.json()
            for asset in assets:
                if asset["target"] == target:
                    return asset
    return None

def start_scan_and_get_error(asset_id, tool, options):
    """Start a scan and return the detailed error message"""
    scan_data = {
        "asset_id": asset_id,
        "tool": tool,
        "options": options
    }
    
    response = requests.post(f"{BASE_URL}/scans/", json=scan_data)
    if response.status_code == 201:
        scan = response.json()
        scan_id = scan["id"]
        
        # Wait for scan to complete or fail
        for _ in range(10):  # Wait up to 50 seconds
            time.sleep(5)
            status_response = requests.get(f"{BASE_URL}/scans/{scan_id}/status")
            
            if status_response.status_code == 200:
                status = status_response.json()
                if status["status"] in ["completed", "failed"]:
                    return {
                        "status": status["status"],
                        "error": status.get("error_message", "No error"),
                        "progress_message": status.get("progress_message", "No progress message")
                    }
        
        return {"status": "timeout", "error": "Scan timed out"}
    else:
        return {"status": "start_failed", "error": f"Failed to start: {response.status_code}"}

def main():
    print("=== SecDash Improved Error Handling Demo ===\n")
    
    # Test 1: Invalid hostname with Nmap
    print("1. Testing Nmap with invalid hostname:")
    invalid_asset = create_test_asset("Invalid Host Test", "nonexistent-host-12345.invalid")
    if invalid_asset:
        result = start_scan_and_get_error(invalid_asset["id"], "nmap", {
            "scan_type": "tcp_syn",
            "port_range": "80,443"
        })
        print(f"   Status: {result['status']}")
        print(f"   Error: {result['error']}\n")
    
    # Test 2: ZAP with invalid web target
    print("2. Testing ZAP with invalid web target:")
    invalid_web_asset = create_test_asset("Invalid Web Test", "http://nonexistent-web-12345.invalid", "web_application")
    if invalid_web_asset:
        result = start_scan_and_get_error(invalid_web_asset["id"], "zap", {
            "scan_type": "baseline",
            "spider_minutes": 1
        })
        print(f"   Status: {result['status']}")
        print(f"   Error: {result['error']}\n")
    
    # Test 3: Nuclei with invalid target
    print("3. Testing Nuclei with invalid target:")
    if invalid_web_asset:
        result = start_scan_and_get_error(invalid_web_asset["id"], "nuclei", {
            "scan_type": "cve",
            "severity": ["high"]
        })
        print(f"   Status: {result['status']}")
        print(f"   Error: {result['error']}\n")
    
    # Test 4: Valid target (should work)
    print("4. Testing Nmap with valid target:")
    valid_asset = create_test_asset("Valid Nmap Test", "scanme.nmap.org")
    if valid_asset:
        result = start_scan_and_get_error(valid_asset["id"], "nmap", {
            "scan_type": "tcp_syn",
            "port_range": "22,80,443"
        })
        print(f"   Status: {result['status']}")
        if result['status'] == 'completed':
            print(f"   Success: Scan completed successfully")
        else:
            print(f"   Error: {result['error']}")
        print()
    
    # Test 5: OpenVAS (should show setup message)
    print("5. Testing OpenVAS (complex setup):")
    if valid_asset:
        result = start_scan_and_get_error(valid_asset["id"], "openvas", {
            "config": "Full and fast"
        })
        print(f"   Status: {result['status']}")
        print(f"   Error: {result['error']}\n")
    
    print("=== Demo Complete ===")
    print("Notice how each error message is specific and actionable!")

if __name__ == "__main__":
    main()
