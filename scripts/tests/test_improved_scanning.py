"""
Test script to demonstrate improved scanning functionality with detailed error reporting
"""
import asyncio
import json
import time
from uuid import UUID, uuid4
import requests
from typing import Dict, List, Any

BASE_URL = "http://localhost:8000/api/v1"

class ImprovedScanTester:
    def __init__(self, base_url: str = BASE_URL):
        self.base_url = base_url
        self.test_results = {}
        
    def print_header(self, title: str):
        """Print a formatted test section header"""
        print("\n" + "="*80)
        print(f" {title}")
        print("="*80)
    
    def print_step(self, step: str, result: str = None):
        """Print a test step"""
        if result:
            status = "✅ PASS" if "✅" in result or "success" in result.lower() else "❌ FAIL"
            print(f"{status} {step}: {result}")
        else:
            print(f"🔄 {step}")
    
    def test_target_validation_and_errors(self) -> bool:
        """Test different tools with various targets to see detailed error messages"""
        self.print_header("Target Validation and Error Testing")
        
        # Create test assets with different target formats
        test_targets = [
            {
                "name": "Valid Nmap Target",
                "type": "host",
                "target": "scanme.nmap.org",
                "description": "Valid target for Nmap scanning"
            },
            {
                "name": "Invalid Host",
                "type": "host", 
                "target": "nonexistent-host-12345.invalid",
                "description": "Invalid hostname to test error handling"
            },
            {
                "name": "Web Target for ZAP",
                "type": "web_application",
                "target": "http://scanme.nmap.org",
                "description": "Web target for ZAP testing"
            },
            {
                "name": "Invalid Web Target",
                "type": "web_application",
                "target": "http://nonexistent-site-12345.invalid",
                "description": "Invalid web target to test ZAP error handling"
            }
        ]
        
        # Create assets
        created_assets = []
        for target_data in test_targets:
            try:
                response = requests.post(f"{self.base_url}/assets/", json=target_data)
                if response.status_code == 201:
                    asset = response.json()
                    created_assets.append(asset)
                    self.print_step(f"Create {target_data['name']}", f"✅ Created with ID: {asset['id']}")
                else:
                    self.print_step(f"Create {target_data['name']}", f"❌ Failed: {response.status_code}")
            except Exception as e:
                self.print_step(f"Create {target_data['name']}", f"❌ Error: {e}")
        
        # Test different scan configurations
        test_scans = [
            {
                "tool": "nmap",
                "asset_name": "Valid Nmap Target",
                "options": {
                    "scan_type": "tcp_syn",
                    "port_range": "22,80,443",
                    "timing": "-T4"
                },
                "expected": "success"
            },
            {
                "tool": "nmap", 
                "asset_name": "Invalid Host",
                "options": {
                    "scan_type": "tcp_syn",
                    "port_range": "22,80,443",
                    "timing": "-T4"
                },
                "expected": "name resolution error"
            },
            {
                "tool": "zap",
                "asset_name": "Web Target for ZAP",
                "options": {
                    "scan_type": "baseline",
                    "spider_minutes": 1
                },
                "expected": "success or connection error"
            },
            {
                "tool": "zap",
                "asset_name": "Invalid Web Target", 
                "options": {
                    "scan_type": "baseline",
                    "spider_minutes": 1
                },
                "expected": "connection error"
            },
            {
                "tool": "nuclei",
                "asset_name": "Web Target for ZAP",
                "options": {
                    "scan_type": "cve",
                    "severity": ["medium", "high", "critical"]
                },
                "expected": "success or no results"
            },
            {
                "tool": "nuclei",
                "asset_name": "Invalid Web Target",
                "options": {
                    "scan_type": "cve", 
                    "severity": ["medium", "high"]
                },
                "expected": "connection error"
            },
            {
                "tool": "metasploit",
                "asset_name": "Valid Nmap Target",
                "options": {
                    "scan_type": "port_scan",
                    "ports": "22,80,443"
                },
                "expected": "success or docker error"
            },
            {
                "tool": "nikto",
                "asset_name": "Web Target for ZAP",
                "options": {
                    "scan_type": "web_scan",
                    "check_outdated": True
                },
                "expected": "success or connection error"
            },
            {
                "tool": "tshark",
                "asset_name": "Valid Nmap Target",
                "options": {
                    "duration": 10,
                    "packet_count": 100
                },
                "expected": "success or capability error"
            },
            {
                "tool": "openvas",
                "asset_name": "Valid Nmap Target", 
                "options": {
                    "config": "Full and fast"
                },
                "expected": "setup error message"
            }
        ]
        
        # Execute test scans
        success_count = 0
        for scan_config in test_scans:
            try:
                # Find the asset for this scan
                target_asset = None
                for asset in created_assets:
                    if asset["name"] == scan_config["asset_name"]:
                        target_asset = asset
                        break
                
                if not target_asset:
                    self.print_step(f"{scan_config['tool']} on {scan_config['asset_name']}", 
                                  "❌ Asset not found")
                    continue
                
                # Start the scan
                scan_data = {
                    "asset_id": target_asset["id"],
                    "tool": scan_config["tool"],
                    "options": scan_config["options"]
                }
                
                response = requests.post(f"{self.base_url}/scans/", json=scan_data)
                if response.status_code == 201:
                    scan = response.json()
                    scan_id = scan["id"]
                    
                    self.print_step(f"Start {scan_config['tool']} scan", 
                                  f"✅ Started with ID: {scan_id}")
                    
                    # Monitor scan for detailed error messages
                    for attempt in range(12):  # Check for up to 60 seconds
                        time.sleep(5)
                        status_response = requests.get(f"{self.base_url}/scans/{scan_id}/status")
                        
                        if status_response.status_code == 200:
                            status = status_response.json()
                            current_status = status['status']
                            progress_msg = status.get('progress_message', 'No message')
                            
                            self.print_step(f"  {scan_config['tool']} Progress", 
                                          f"🔄 {current_status} - {progress_msg}")
                            
                            if current_status in ['completed', 'failed', 'cancelled']:
                                if current_status == 'completed':
                                    findings_count = status.get('findings_count', 0)
                                    self.print_step(f"Complete {scan_config['tool']}", 
                                                  f"✅ Success - {findings_count} findings")
                                    success_count += 1
                                    
                                    # Store results for analysis
                                    self.test_results[f"{scan_config['tool']}_{scan_config['asset_name']}"] = {
                                        "status": "completed",
                                        "findings": findings_count,
                                        "expected": scan_config["expected"]
                                    }
                                else:
                                    # Get detailed error information
                                    error_msg = status.get('error_message', 'No error details')
                                    self.print_step(f"Complete {scan_config['tool']}", 
                                                  f"❌ {current_status}: {error_msg}")
                                    
                                    # Store error details for analysis
                                    self.test_results[f"{scan_config['tool']}_{scan_config['asset_name']}"] = {
                                        "status": current_status,
                                        "error": error_msg,
                                        "expected": scan_config["expected"]
                                    }
                                    
                                    # Check if error message is detailed enough
                                    if len(error_msg) > 50 and any(keyword in error_msg.lower() for keyword in 
                                        ["could not resolve", "connection refused", "docker", "timeout", "permission"]):
                                        self.print_step(f"  Error Detail Quality", "✅ Detailed error message provided")
                                    else:
                                        self.print_step(f"  Error Detail Quality", "❌ Generic error message")
                                
                                break
                        else:
                            self.print_step(f"  {scan_config['tool']} Status Check", 
                                          f"❌ Failed to get status: {status_response.status_code}")
                            break
                    
                else:
                    error_detail = response.json() if response.headers.get('content-type', '').startswith('application/json') else response.text
                    self.print_step(f"Start {scan_config['tool']} scan", 
                                  f"❌ Failed to start: {response.status_code} - {error_detail}")
                    
            except Exception as e:
                self.print_step(f"{scan_config['tool']} scan test", f"❌ Exception: {e}")
        
        return success_count > 0
    
    def analyze_results(self):
        """Analyze and report on the test results"""
        self.print_header("Test Results Analysis")
        
        if not self.test_results:
            self.print_step("Analysis", "❌ No test results to analyze")
            return
        
        completed_scans = 0
        failed_scans = 0
        detailed_errors = 0
        
        for test_name, result in self.test_results.items():
            tool, target = test_name.split('_', 1)
            
            if result["status"] == "completed":
                completed_scans += 1
                self.print_step(f"{tool} on {target}", 
                              f"✅ Completed with {result['findings']} findings")
            else:
                failed_scans += 1
                error_msg = result.get("error", "No error message")
                
                # Check error message quality
                if len(error_msg) > 30 and not error_msg.startswith("Scan failed"):
                    detailed_errors += 1
                    self.print_step(f"{tool} on {target}", 
                                  f"✅ Failed with detailed error: {error_msg[:100]}...")
                else:
                    self.print_step(f"{tool} on {target}", 
                                  f"❌ Failed with generic error: {error_msg}")
        
        # Summary
        total_tests = len(self.test_results)
        self.print_step("Total Tests", f"{total_tests}")
        self.print_step("Completed Scans", f"{completed_scans} ({completed_scans/total_tests*100:.1f}%)")
        self.print_step("Failed Scans", f"{failed_scans} ({failed_scans/total_tests*100:.1f}%)")
        self.print_step("Detailed Error Messages", f"{detailed_errors}/{failed_scans} ({detailed_errors/max(failed_scans,1)*100:.1f}%)")
    
    def run_all_tests(self):
        """Run all test scenarios"""
        self.print_header("SecDash Improved Scanning Tests")
        
        # Test API connectivity first
        try:
            response = requests.get(f"{self.base_url}/scans/stats/overview", timeout=10)
            if response.status_code == 200:
                self.print_step("API Connectivity", "✅ Connected to SecDash API")
            else:
                self.print_step("API Connectivity", f"❌ API returned status {response.status_code}")
                return False
        except Exception as e:
            self.print_step("API Connectivity", f"❌ Cannot connect to API: {e}")
            return False
        
        # Run main tests
        success = self.test_target_validation_and_errors()
        
        # Analyze results
        self.analyze_results()
        
        return success

if __name__ == "__main__":
    tester = ImprovedScanTester()
    success = tester.run_all_tests()
    
    if success:
        print("\n🎉 Test completed - Check results above for detailed error handling improvements")
    else:
        print("\n❌ Tests failed - Check API connectivity and service status")
