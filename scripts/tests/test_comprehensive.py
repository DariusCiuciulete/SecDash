"""
Comprehensive test script for SecDash functionality
"""
import asyncio
import json
import time
from uuid import UUID, uuid4
import requests
from typing import Dict, List, Any

BASE_URL = "http://localhost:8000/api/v1"

class SecDashTester:
    def __init__(self, base_url: str = BASE_URL):
        self.base_url = base_url
        self.test_assets = []
        self.test_scans = []
        
    def print_header(self, title: str):
        """Print a formatted test section header"""
        print("\n" + "="*60)
        print(f" {title}")
        print("="*60)
    
    def print_step(self, step: str, result: str = None):
        """Print a test step"""
        if result:
            status = "✅ PASS" if "✅" in result or "success" in result.lower() else "❌ FAIL"
            print(f"{status} {step}: {result}")
        else:
            print(f"🔄 {step}")
    
    def test_api_connectivity(self) -> bool:
        """Test basic API connectivity"""
        self.print_header("API Connectivity Test")
        
        try:
            response = requests.get(f"{self.base_url}/scans/stats/overview", timeout=10)
            if response.status_code == 200:
                stats = response.json()
                self.print_step("API Connection", f"✅ Connected - {stats.get('total_scans', 0)} total scans")
                return True
            else:
                self.print_step("API Connection", f"❌ Failed with status {response.status_code}")
                return False
        except Exception as e:
            self.print_step("API Connection", f"❌ Error: {e}")
            return False
    
    def test_scan_profiles(self) -> bool:
        """Test scan profile endpoints"""
        self.print_header("Scan Profiles Test")
        
        try:
            # Test getting all profiles
            response = requests.get(f"{self.base_url}/profiles/")
            if response.status_code == 200:
                profiles = response.json()
                tools = list(profiles.keys())
                self.print_step("Get All Profiles", f"✅ Found {len(tools)} tools: {', '.join(tools)}")
                
                # Test each tool's profiles
                for tool in tools:
                    tool_response = requests.get(f"{self.base_url}/profiles/{tool}")
                    if tool_response.status_code == 200:
                        tool_profiles = tool_response.json()
                        profile_names = list(tool_profiles.keys())
                        self.print_step(f"{tool.upper()} Profiles", f"✅ {len(profile_names)} profiles available")
                    else:
                        self.print_step(f"{tool.upper()} Profiles", f"❌ Failed to fetch")
                
                # Test supported tools endpoint
                tools_response = requests.get(f"{self.base_url}/profiles/tools/list")
                if tools_response.status_code == 200:
                    tools_data = tools_response.json()
                    self.print_step("Supported Tools", f"✅ {len(tools_data['tools'])} tools supported")
                
                return True
            else:
                self.print_step("Get All Profiles", f"❌ Failed with status {response.status_code}")
                return False
                
        except Exception as e:
            self.print_step("Scan Profiles", f"❌ Error: {e}")
            return False
    
    def create_test_assets(self) -> bool:
        """Create test assets for scanning"""
        self.print_header("Test Asset Creation")
        
        test_assets_data = [
            {
                "name": "Scanme Nmap Official",
                "type": "host",
                "target": "scanme.nmap.org",
                "description": "Official Nmap test target",
                "tags": ["test", "public"]
            },
            {
                "name": "Local Test Server",
                "type": "host", 
                "target": "127.0.0.1",
                "description": "Local server for testing",
                "tags": ["test", "local"]
            },
            {
                "name": "Test Web Application",
                "type": "web_application",
                "target": "http://testphp.vulnweb.com/",
                "description": "Vulnerable web app for testing",
                "tags": ["test", "webapp"]
            }
        ]
        
        try:
            for asset_data in test_assets_data:
                response = requests.post(f"{self.base_url}/assets/", json=asset_data)
                if response.status_code == 201:
                    asset = response.json()
                    self.test_assets.append(asset)
                    self.print_step(f"Create {asset_data['name']}", f"✅ Created with ID: {asset['id']}")
                else:
                    self.print_step(f"Create {asset_data['name']}", f"❌ Failed: {response.status_code}")
            
            return len(self.test_assets) > 0
            
        except Exception as e:
            self.print_step("Asset Creation", f"❌ Error: {e}")
            return False
    
    def test_nmap_scans(self) -> bool:
        """Test various Nmap scan configurations"""
        self.print_header("Nmap Scan Tests")
        
        if not self.test_assets:
            self.print_step("Nmap Tests", "❌ No test assets available")
            return False
        
        # Use the first asset (scanme.nmap.org)
        asset = self.test_assets[0]
        
        nmap_tests = [
            {
                "name": "TCP SYN Scan",
                "options": {
                    "scan_type": "tcp_syn",
                    "port_range": "22,80,443",
                    "timing": "-T4"
                }
            },
            {
                "name": "UDP Scan",
                "options": {
                    "scan_type": "udp", 
                    "top_ports": "10",
                    "timing": "-T4"
                }
            },
            {
                "name": "Service Detection",
                "options": {
                    "scan_type": "service_detection",
                    "port_range": "22,80,443",
                    "timing": "-T4",
                    "enable_scripts": True
                }
            }
        ]
        
        success_count = 0
        
        for test in nmap_tests:
            try:
                scan_data = {
                    "asset_id": asset["id"],
                    "tool": "nmap",
                    "options": test["options"]
                }
                
                response = requests.post(f"{self.base_url}/scans/", json=scan_data)
                if response.status_code == 201:
                    scan = response.json()
                    self.test_scans.append(scan)
                    scan_id = scan["id"]
                    
                    # Monitor scan progress
                    self.print_step(f"Start {test['name']}", f"✅ Started with ID: {scan_id}")
                    
                    # Wait and check status a few times
                    for i in range(6):  # Check 6 times over 30 seconds
                        time.sleep(5)
                        status_response = requests.get(f"{self.base_url}/scans/{scan_id}/status")
                        if status_response.status_code == 200:
                            status = status_response.json()
                            self.print_step(f"  {test['name']} Status", 
                                          f"🔄 {status['status']} - {status['progress']}% - {status['progress_message']}")
                            
                            if status['status'] in ['completed', 'failed', 'cancelled']:
                                if status['status'] == 'completed':
                                    self.print_step(f"Complete {test['name']}", 
                                                  f"✅ Completed with {status.get('findings_count', 0)} findings")
                                    success_count += 1
                                else:
                                    self.print_step(f"Complete {test['name']}", 
                                                  f"❌ Status: {status['status']}")
                                break
                        else:
                            self.print_step(f"  {test['name']} Status", "❌ Failed to get status")
                            break
                    
                else:
                    self.print_step(f"Start {test['name']}", f"❌ Failed: {response.status_code}")
                    
            except Exception as e:
                self.print_step(f"{test['name']}", f"❌ Error: {e}")
        
        return success_count > 0
    
    def test_zap_scans(self) -> bool:
        """Test ZAP web application scans"""
        self.print_header("ZAP Scan Tests")
        
        # Find web application asset
        web_asset = None
        for asset in self.test_assets:
            if asset.get("type") == "web_application":
                web_asset = asset
                break
        
        if not web_asset:
            self.print_step("ZAP Tests", "❌ No web application asset available")
            return False
        
        zap_tests = [
            {
                "name": "Baseline Scan",
                "options": {
                    "scan_type": "baseline",
                    "spider_minutes": 1,  # Short for testing
                    "ajax_spider": False
                }
            }
        ]
        
        success_count = 0
        
        for test in zap_tests:
            try:
                scan_data = {
                    "asset_id": web_asset["id"],
                    "tool": "zap",
                    "options": test["options"]
                }
                
                response = requests.post(f"{self.base_url}/scans/", json=scan_data)
                if response.status_code == 201:
                    scan = response.json()
                    self.test_scans.append(scan)
                    scan_id = scan["id"]
                    
                    self.print_step(f"Start {test['name']}", f"✅ Started with ID: {scan_id}")
                    
                    # Monitor for longer (ZAP scans take more time)
                    for i in range(12):  # Check 12 times over 60 seconds
                        time.sleep(5)
                        status_response = requests.get(f"{self.base_url}/scans/{scan_id}/status")
                        if status_response.status_code == 200:
                            status = status_response.json()
                            self.print_step(f"  {test['name']} Status", 
                                          f"🔄 {status['status']} - {status['progress']}% - {status['progress_message']}")
                            
                            if status['status'] in ['completed', 'failed', 'cancelled']:
                                if status['status'] == 'completed':
                                    self.print_step(f"Complete {test['name']}", 
                                                  f"✅ Completed with {status.get('findings_count', 0)} findings")
                                    success_count += 1
                                else:
                                    self.print_step(f"Complete {test['name']}", 
                                                  f"❌ Status: {status['status']}")
                                break
                    
                else:
                    self.print_step(f"Start {test['name']}", f"❌ Failed: {response.status_code}")
                    
            except Exception as e:
                self.print_step(f"{test['name']}", f"❌ Error: {e}")
        
        return success_count > 0
    
    def test_scan_management(self) -> bool:
        """Test scan management features"""
        self.print_header("Scan Management Tests")
        
        try:
            # List all scans
            response = requests.get(f"{self.base_url}/scans/")
            if response.status_code == 200:
                scans = response.json()
                total_scans = scans.get("total", 0)
                self.print_step("List Scans", f"✅ Found {total_scans} total scans")
                
                # Test scan details for each test scan
                for scan in self.test_scans:
                    detail_response = requests.get(f"{self.base_url}/scans/{scan['id']}")
                    if detail_response.status_code == 200:
                        details = detail_response.json()
                        self.print_step(f"Get Scan {scan['id'][:8]}...", 
                                      f"✅ Status: {details['status']}")
                    else:
                        self.print_step(f"Get Scan {scan['id'][:8]}...", "❌ Failed")
                
                # Test scan statistics
                stats_response = requests.get(f"{self.base_url}/scans/stats/overview")
                if stats_response.status_code == 200:
                    stats = stats_response.json()
                    self.print_step("Scan Statistics", 
                                  f"✅ Total: {stats['total_scans']}, By status: {stats['status_counts']}")
                
                return True
            else:
                self.print_step("List Scans", f"❌ Failed: {response.status_code}")
                return False
                
        except Exception as e:
            self.print_step("Scan Management", f"❌ Error: {e}")
            return False
    
    def test_vulnerability_data(self) -> bool:
        """Test vulnerability data retrieval"""
        self.print_header("Vulnerability Data Tests")
        
        try:
            # List vulnerabilities
            response = requests.get(f"{self.base_url}/vulnerabilities/")
            if response.status_code == 200:
                vulns = response.json()
                total_vulns = vulns.get("total", 0)
                self.print_step("List Vulnerabilities", f"✅ Found {total_vulns} vulnerabilities")
                
                if total_vulns > 0:
                    # Test first vulnerability details
                    first_vuln = vulns["items"][0]
                    detail_response = requests.get(f"{self.base_url}/vulnerabilities/{first_vuln['id']}")
                    if detail_response.status_code == 200:
                        vuln_details = detail_response.json()
                        self.print_step("Vulnerability Details", 
                                      f"✅ {vuln_details['name']} - Severity: {vuln_details['severity']}")
                
                return True
            else:
                self.print_step("List Vulnerabilities", f"❌ Failed: {response.status_code}")
                return False
                
        except Exception as e:
            self.print_step("Vulnerability Data", f"❌ Error: {e}")
            return False
    
    def cleanup_test_data(self) -> bool:
        """Clean up test assets and scans"""
        self.print_header("Cleanup Test Data")
        
        success = True
        
        # Cancel any running scans
        for scan in self.test_scans:
            try:
                cancel_response = requests.post(f"{self.base_url}/scans/{scan['id']}/cancel")
                if cancel_response.status_code == 200:
                    self.print_step(f"Cancel Scan {scan['id'][:8]}...", "✅ Cancelled")
                else:
                    self.print_step(f"Cancel Scan {scan['id'][:8]}...", "🔄 May not be running")
            except Exception as e:
                self.print_step(f"Cancel Scan {scan['id'][:8]}...", f"❌ Error: {e}")
        
        # Delete test assets
        for asset in self.test_assets:
            try:
                delete_response = requests.delete(f"{self.base_url}/assets/{asset['id']}")
                if delete_response.status_code == 204:
                    self.print_step(f"Delete Asset {asset['name']}", "✅ Deleted")
                else:
                    self.print_step(f"Delete Asset {asset['name']}", f"❌ Failed: {delete_response.status_code}")
                    success = False
            except Exception as e:
                self.print_step(f"Delete Asset {asset['name']}", f"❌ Error: {e}")
                success = False
        
        return success
    
    def run_all_tests(self) -> Dict[str, bool]:
        """Run all tests and return results"""
        results = {}
        
        print("🚀 Starting SecDash Comprehensive Test Suite")
        print(f"📡 Testing against: {self.base_url}")
        
        # Run tests in order
        results["connectivity"] = self.test_api_connectivity()
        results["profiles"] = self.test_scan_profiles()
        results["asset_creation"] = self.create_test_assets()
        results["nmap_scans"] = self.test_nmap_scans()
        results["zap_scans"] = self.test_zap_scans()
        results["scan_management"] = self.test_scan_management()
        results["vulnerability_data"] = self.test_vulnerability_data()
        results["cleanup"] = self.cleanup_test_data()
        
        # Print summary
        self.print_header("Test Summary")
        passed = sum(1 for result in results.values() if result)
        total = len(results)
        
        for test_name, result in results.items():
            status = "✅ PASS" if result else "❌ FAIL"
            self.print_step(test_name.replace("_", " ").title(), status)
        
        print(f"\n🎯 Overall Result: {passed}/{total} tests passed")
        
        if passed == total:
            print("🎉 All tests passed! Your SecDash implementation is working correctly.")
        else:
            print("⚠️  Some tests failed. Check the output above for details.")
        
        return results


def main():
    """Main test function"""
    tester = SecDashTester()
    results = tester.run_all_tests()
    
    # Exit with appropriate code
    all_passed = all(results.values())
    exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
