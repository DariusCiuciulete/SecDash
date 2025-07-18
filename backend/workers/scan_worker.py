"""
Celery worker for security scan processing
"""
import asyncio
import json
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Optional
from uuid import UUID

from celery import current_task
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from celery_app import celery_app
from database import db_manager
from models import Scan, Asset, Vulnerability, ScanStatus, VulnerabilitySeverity
from transformers import (
    nmap_to_unified, zap_to_unified, nuclei_to_unified,
    metasploit_to_unified, tshark_to_unified, openvas_to_unified,
    nikto_to_unified
)
from config import settings


class MockDockerClient:
    """Mock Docker client for testing when Docker is not available"""
    
    def __init__(self):
        pass
    
    @property
    def containers(self):
        return MockContainers()


class MockContainers:
    """Mock containers interface"""
    
    def run(self, *args, **kwargs):
        """Mock container run method"""
        return MockContainer()


class MockContainer:
    """Mock container"""
    
    def wait(self, timeout=None):
        return {"StatusCode": 0}
    
    def logs(self):
        return b"Mock scan output - no Docker available"
    
    def kill(self):
        pass


class ScanWorker:
    """Security scan worker class"""
    
    def __init__(self):
        self._docker_client = None
        self.docker_network = settings.scanners.docker_network
    
    @property
    def docker_client(self):
        """Lazy initialization of Docker client"""
        if self._docker_client is None:
            try:
                import docker
                self._docker_client = docker.from_env()
            except Exception as e:
                # Log error but don't fail initialization
                print(f"Warning: Could not initialize Docker client: {e}")
                # Create a mock docker client for testing
                self._docker_client = MockDockerClient()
        return self._docker_client
    
    async def execute_scan(self, scan_id: str) -> Dict[str, Any]:
        """Execute a security scan"""
        async with db_manager.get_session() as session:
            # Get scan details
            scan = await self._get_scan(session, scan_id)
            if not scan:
                raise ValueError(f"Scan {scan_id} not found")
            
            # Get asset details
            asset = await self._get_asset(session, scan.asset_id)
            if not asset:
                raise ValueError(f"Asset {scan.asset_id} not found")
            
            try:
                # Update scan status to running with start time
                start_time = datetime.utcnow()
                await self._update_scan_status(session, scan_id, ScanStatus.RUNNING, 
                                             started_at=start_time)
                
                # Update task progress
                if current_task:
                    current_task.update_state(
                        state="PROGRESS", 
                        meta={
                            "step": "initializing",
                            "progress": 10,
                            "message": f"Starting {scan.tool} scan for {asset.target}"
                        }
                    )
                
                # Execute the actual scan
                raw_output = await self._run_scan_container(scan.tool, asset.target, scan.options)
                
                # Update task progress
                if current_task:
                    current_task.update_state(
                        state="PROGRESS", 
                        meta={
                            "step": "processing_results",
                            "progress": 80,
                            "message": "Processing scan results"
                        }
                    )
                
                # Transform raw output to unified format
                findings = await self._transform_scan_results(
                    scan.tool, raw_output, scan_id, asset.target
                )
                
                # Store vulnerabilities
                vulnerability_count = await self._store_vulnerabilities(
                    session, findings, scan.asset_id, UUID(scan_id)
                )
                
                # Update task progress
                if current_task:
                    current_task.update_state(
                        state="PROGRESS", 
                        meta={
                            "step": "completing",
                            "progress": 95,
                            "message": f"Scan completed with {vulnerability_count} findings"
                        }
                    )
                
                # Update scan with results
                end_time = datetime.utcnow()
                duration = int((end_time - start_time).total_seconds())
                
                await self._update_scan_completion(
                    session, scan_id, ScanStatus.COMPLETED, 
                    end_time, duration, raw_output, vulnerability_count
                )
                
                return {
                    "status": "completed",
                    "findings_count": vulnerability_count,
                    "duration_seconds": duration,
                    "start_time": start_time.isoformat(),
                    "end_time": end_time.isoformat()
                }
                
            except Exception as e:
                # Update scan status to failed
                end_time = datetime.utcnow()
                scan_record = await self._get_scan(session, scan_id)
                start_time = scan_record.started_at if scan_record and scan_record.started_at else end_time
                duration = int((end_time - start_time).total_seconds())
                
                await self._update_scan_status(
                    session, scan_id, ScanStatus.FAILED,
                    error_message=str(e),
                    completed_at=end_time,
                    duration_seconds=duration
                )
                
                if current_task:
                    current_task.update_state(
                        state="FAILURE", 
                        meta={
                            "step": "failed",
                            "progress": 0,
                            "message": f"Scan failed: {str(e)}"
                        }
                    )
                raise
    
    async def _get_scan(self, session: AsyncSession, scan_id: str) -> Optional[Scan]:
        """Get scan by ID"""
        result = await session.execute(
            select(Scan).where(Scan.id == UUID(scan_id))
        )
        return result.scalar_one_or_none()
    
    async def _get_asset(self, session: AsyncSession, asset_id: UUID) -> Optional[Asset]:
        """Get asset by ID"""
        result = await session.execute(
            select(Asset).where(Asset.id == asset_id)
        )
        return result.scalar_one_or_none()
    
    async def _update_scan_status(self, session: AsyncSession, scan_id: str, 
                                status: ScanStatus, **kwargs):
        """Update scan status and other fields"""
        update_data = {"status": status, **kwargs}
        await session.execute(
            update(Scan).where(Scan.id == UUID(scan_id)).values(**update_data)
        )
        await session.commit()
    
    async def _update_scan_completion(self, session: AsyncSession, scan_id: str,
                                    status: ScanStatus, completed_at: datetime,
                                    duration: int, raw_output: str, findings_count: int):
        """Update scan completion details"""
        await session.execute(
            update(Scan).where(Scan.id == UUID(scan_id)).values(
                status=status,
                completed_at=completed_at,
                duration_seconds=duration,
                raw_output=raw_output,
                findings_count=findings_count
            )
        )
        await session.commit()
    
    async def _run_scan_container(self, tool: str, target: str, options: Dict[str, Any]) -> str:
        """Run security scan in Docker container"""
        # Update task progress
        if current_task:
            current_task.update_state(
                state="PROGRESS", 
                meta={
                    "step": "starting_container",
                    "progress": 20,
                    "message": f"Starting {tool} container"
                }
            )
        
        # Validate target format for each tool
        try:
            validated_target = self._validate_target_for_tool(tool, target)
        except ValueError as e:
            raise ValueError(f"Target validation failed for {tool}: {str(e)}")
        
        if tool == "nmap":
            return await self._run_nmap(validated_target, options)
        elif tool == "zap":
            return await self._run_zap(validated_target, options)
        elif tool == "nuclei":
            return await self._run_nuclei(validated_target, options)
        elif tool == "metasploit":
            return await self._run_metasploit(validated_target, options)
        elif tool == "tshark":
            return await self._run_tshark(validated_target, options)
        elif tool == "openvas":
            return await self._run_openvas(validated_target, options)
        elif tool == "nikto":
            return await self._run_nikto(validated_target, options)
        else:
            raise ValueError(f"Unsupported scan tool: {tool}")
    
    def _validate_target_for_tool(self, tool: str, target: str) -> str:
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
    
    async def _run_nmap(self, target: str, options: Dict[str, Any]) -> str:
        """Run Nmap scan using Docker or native nmap"""
        # Update progress
        if current_task:
            current_task.update_state(
                state="PROGRESS", 
                meta={
                    "step": "configuring_nmap",
                    "progress": 30,
                    "message": f"Configuring Nmap scan for {target}"
                }
            )
        
        # Get scan configuration from options
        scan_type = options.get("scan_type", "tcp_syn")
        port_range = options.get("port_range", "1-1000")
        timing = options.get("timing", "-T4")
        enable_scripts = options.get("enable_scripts", False)
        os_detection = options.get("os_detection", False)
        
        # Build command based on scan type
        if scan_type == "tcp_syn":
            command = f"nmap -sS -Pn {timing} -p {port_range} {target}"
        elif scan_type == "tcp_connect":
            command = f"nmap -sT -Pn {timing} -p {port_range} {target}"
        elif scan_type == "udp":
            top_ports = options.get("top_ports", "100")
            command = f"nmap -sU -Pn {timing} --top-ports {top_ports} {target}"
        elif scan_type == "service_detection":
            command = f"nmap -sS -sV -Pn {timing} -p {port_range} {target}"
            if os_detection:
                command += " -O"
            if enable_scripts:
                command += " -sC"
        elif scan_type == "comprehensive":
            command = f"nmap -sS -sV -sC -O -A -Pn {timing} -p {port_range} {target}"
        elif scan_type == "vulnerability_scan":
            command = f"nmap -sS -sV --script vuln -Pn {timing} -p {port_range} {target}"
        else:
            # Fallback using old format for compatibility
            base_cmd = options.get("command", "nmap -Pn")
            ports = options.get("ports", port_range)
            timing_flag = options.get("timing", "T4")
            command = f"{base_cmd} -p {ports} -{timing_flag} {target}"
        
        # Try Docker first, then fallback to native nmap
        try:
            import docker
            docker_client = docker.from_env()
            docker_client.ping()  # Test if Docker is actually running
            
            # Update progress
            if current_task:
                current_task.update_state(
                    state="PROGRESS", 
                    meta={
                        "step": "running_docker_scan",
                        "progress": 50,
                        "message": f"Running Nmap scan in Docker: {command}"
                    }
                )
            
            # Run container
            container = self.docker_client.containers.run(
                image=settings.scanners.nmap_image,
                command=command,
                detach=True,
                network=self.docker_network,
                remove=True,
                mem_limit="512m",
                cpu_period=100000,
                cpu_quota=50000,  # 50% CPU limit
            )
            
            # Wait for completion with timeout
            try:
                result = container.wait(timeout=settings.scanners.scan_timeout)
                logs = container.logs().decode("utf-8")
                
                if result["StatusCode"] != 0:
                    raise RuntimeError(f"Nmap scan failed with exit code {result['StatusCode']}")
                
                # Update progress
                if current_task:
                    current_task.update_state(
                        state="PROGRESS", 
                        meta={
                            "step": "scan_completed",
                            "progress": 70,
                            "message": "Nmap scan completed successfully"
                        }
                    )
                
                return logs
                
            except Exception as e:
                # Kill container if still running
                try:
                    container.kill()
                except:
                    pass
                raise RuntimeError(f"Nmap Docker scan failed: {str(e)}")
                
        except Exception as docker_error:
            # Fallback to native nmap if Docker fails
            print(f"Docker unavailable ({docker_error}), trying native nmap...")
            
            try:
                import subprocess
                import asyncio
                
                # Extract basic options for native command
                ports = options.get("port_range", "1-1000")
                timing = options.get("timing", "T4").replace("-", "")
                
                # Try to run native nmap
                process = await asyncio.create_subprocess_exec(
                    "nmap", "-Pn", "-p", ports, f"-{timing}", target,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), 
                    timeout=settings.scanners.scan_timeout
                )
                
                if process.returncode == 0:
                    return stdout.decode("utf-8")
                else:
                    error_detail = stderr.decode('utf-8') if stderr else "Unknown error"
                    raise RuntimeError(f"Native nmap failed (exit code {process.returncode}): {error_detail}")
                    
            except FileNotFoundError:
                raise RuntimeError(f"Both Docker and native nmap are unavailable. Docker error: {docker_error}. Nmap not found in PATH.")
            except asyncio.TimeoutError:
                raise RuntimeError(f"Nmap scan timed out after {settings.scanners.scan_timeout} seconds")
            except Exception as native_error:
                raise RuntimeError(f"Both Docker and native nmap failed. Docker: {docker_error}. Native: {native_error}")
    async def _run_zap(self, target: str, options: Dict[str, Any]) -> str:
        """Run OWASP ZAP scan"""
        scan_type = options.get("scan_type", "baseline")
        spider_minutes = options.get("spider_minutes", 2)
        ajax_spider = options.get("ajax_spider", False)
        
        # Update progress
        if current_task:
            current_task.update_state(
                state="PROGRESS", 
                meta={
                    "step": "configuring_zap",
                    "progress": 35,
                    "message": f"Configuring ZAP {scan_type} scan"
                }
            )
        
        # Validate target is a URL
        if not target.startswith(('http://', 'https://')):
            raise ValueError(f"ZAP requires HTTP/HTTPS URL, got: {target}")
        
        # Build command based on scan type
        if scan_type == "baseline":
            command = f"zap-baseline.py -t {target} -J /zap/wrk/report.json"
            if spider_minutes != 2:
                command += f" -m {spider_minutes}"
        elif scan_type == "full":
            command = f"zap-full-scan.py -t {target} -J /zap/wrk/report.json"
            if spider_minutes != 5:
                command += f" -m {spider_minutes}"
        elif scan_type == "api":
            api_format = options.get("api_format", "openapi")
            command = f"zap-api-scan.py -t {target} -f {api_format} -J /zap/wrk/report.json"
        else:
            raise ValueError(f"Unsupported ZAP scan type: {scan_type}")
        
        # Add additional options
        if ajax_spider:
            command += " -j"  # Enable AJAX spider
        
        # Create volume for reports
        volumes = {"/tmp/zap": {"bind": "/zap/wrk", "mode": "rw"}}
        
        # Update progress
        if current_task:
            current_task.update_state(
                state="PROGRESS", 
                meta={
                    "step": "running_zap_scan",
                    "progress": 45,
                    "message": f"Running ZAP scan: {command}"
                }
            )
        
        try:
            # Check if Docker is available
            try:
                import docker
                docker_client = docker.from_env()
                docker_client.ping()
            except Exception as docker_error:
                raise RuntimeError(f"Docker unavailable for ZAP scan: {docker_error}. ZAP requires Docker to run.")
        
            container = self.docker_client.containers.run(
                image=settings.scanners.zap_image,
                command=command,
                detach=True,
                network=self.docker_network,
                volumes=volumes,
                remove=True,
                mem_limit="1g",
            )
            
            try:
                result = container.wait(timeout=settings.scanners.scan_timeout)
                logs = container.logs().decode("utf-8")
                
                # ZAP returns non-zero exit codes even for successful scans with findings
                # Check for actual error indicators in logs
                if "Connection refused" in logs:
                    raise RuntimeError(f"ZAP could not connect to target {target}. Target may be unreachable or not running a web server.")
                elif "No such host" in logs or "could not resolve" in logs:
                    raise RuntimeError(f"ZAP could not resolve hostname in {target}. Check target URL validity.")
                elif "timeout" in logs.lower():
                    raise RuntimeError(f"ZAP scan timed out connecting to {target}")
                elif result["StatusCode"] > 2:  # ZAP returns 1-2 for findings, >2 for actual errors
                    raise RuntimeError(f"ZAP scan failed with exit code {result['StatusCode']}: {logs[-500:]}")  # Last 500 chars of logs
                
                return logs
                
            except Exception as e:
                try:
                    container.kill()
                except:
                    pass
                if "timeout" in str(e).lower():
                    raise RuntimeError(f"ZAP scan timed out after {settings.scanners.scan_timeout} seconds")
                raise RuntimeError(f"ZAP scan failed: {str(e)}")
                
        except Exception as e:
            if "Docker" in str(e):
                raise  # Re-raise Docker-specific errors
            raise RuntimeError(f"ZAP scan setup failed: {str(e)}")
    
    async def _run_nuclei(self, target: str, options: Dict[str, Any]) -> str:
        """Run Nuclei scan"""
        severity = options.get("severity", "medium,high,critical")
        templates = options.get("templates", "")
        scan_type = options.get("scan_type", "cve")
        
        # Update progress
        if current_task:
            current_task.update_state(
                state="PROGRESS", 
                meta={
                    "step": "configuring_nuclei",
                    "progress": 35,
                    "message": f"Configuring Nuclei {scan_type} scan"
                }
            )
        
        # Build severity filter
        if isinstance(severity, list):
            severity = ",".join(severity)
        
        # Build command
        command = f"nuclei -target {target} -severity {severity}"
        
        # Add templates based on scan type
        if scan_type == "cve":
            command += " -t cves/"
        elif scan_type == "vulnerability":
            command += " -t vulnerabilities/"
        elif scan_type == "misconfiguration":
            command += " -t misconfigurations/"
        elif templates:
            command += f" -t {templates}"
        
        command += " -json -o /tmp/nuclei-output.json"
        
        # Update progress
        if current_task:
            current_task.update_state(
                state="PROGRESS", 
                meta={
                    "step": "running_nuclei_scan",
                    "progress": 45,
                    "message": f"Running Nuclei scan: {command}"
                }
            )
        
        try:
            # Check if Docker is available
            try:
                import docker
                docker_client = docker.from_env()
                docker_client.ping()
            except Exception as docker_error:
                raise RuntimeError(f"Docker unavailable for Nuclei scan: {docker_error}. Nuclei requires Docker to run.")
        
            container = self.docker_client.containers.run(
                image=settings.scanners.nuclei_image,
                command=command,
                detach=True,
                network=self.docker_network,
                remove=True,
                mem_limit="512m",
            )
            
            try:
                result = container.wait(timeout=settings.scanners.scan_timeout)
                logs = container.logs().decode("utf-8")
                
                # Check for specific error patterns
                if "could not resolve" in logs.lower():
                    raise RuntimeError(f"Nuclei could not resolve target {target}. Check target validity.")
                elif "connection refused" in logs.lower():
                    raise RuntimeError(f"Nuclei could not connect to target {target}. Target may be unreachable.")
                elif "no such host" in logs.lower():
                    raise RuntimeError(f"Nuclei could not find host {target}. Check target format.")
                elif result["StatusCode"] != 0 and "No results found" not in logs:
                    # Nuclei returns non-zero when no results found, which is not an error
                    raise RuntimeError(f"Nuclei scan failed with exit code {result['StatusCode']}: {logs[-300:]}")
                
                # If no output in logs, check if it's because no vulnerabilities were found
                if not logs.strip() or "No results found" in logs:
                    return "No vulnerabilities found by Nuclei scan"
                
                return logs
                
            except Exception as e:
                try:
                    container.kill()
                except:
                    pass
                if "timeout" in str(e).lower():
                    raise RuntimeError(f"Nuclei scan timed out after {settings.scanners.scan_timeout} seconds")
                raise RuntimeError(f"Nuclei scan failed: {str(e)}")
                
        except Exception as e:
            if "Docker" in str(e):
                raise  # Re-raise Docker-specific errors
            raise RuntimeError(f"Nuclei scan setup failed: {str(e)}")
    
    async def _run_metasploit(self, target: str, options: Dict[str, Any]) -> str:
        """Run Metasploit scan"""
        scan_type = options.get("scan_type", "port_scan")
        
        # Update progress
        if current_task:
            current_task.update_state(
                state="PROGRESS", 
                meta={
                    "step": "configuring_metasploit",
                    "progress": 35,
                    "message": f"Configuring Metasploit {scan_type} scan"
                }
            )
        
        if scan_type == "port_scan":
            ports = options.get("ports", "1-1000")
            # Use auxiliary scanners for discovery
            command = f"msfconsole -q -x 'use auxiliary/scanner/portscan/tcp; set RHOSTS {target}; set PORTS {ports}; run; exit'"
        elif scan_type == "service_scan":
            # Service discovery
            command = f"msfconsole -q -x 'use auxiliary/scanner/discovery/udp_sweep; set RHOSTS {target}; run; exit'"
        else:
            raise ValueError(f"Unsupported Metasploit scan type: {scan_type}")
        
        # Update progress
        if current_task:
            current_task.update_state(
                state="PROGRESS", 
                meta={
                    "step": "running_metasploit_scan",
                    "progress": 45,
                    "message": f"Running Metasploit scan: {command}"
                }
            )
        
        try:
            # Check if Docker is available
            try:
                import docker
                docker_client = docker.from_env()
                docker_client.ping()
            except Exception as docker_error:
                raise RuntimeError(f"Docker unavailable for Metasploit scan: {docker_error}. Metasploit requires Docker to run.")
        
            container = self.docker_client.containers.run(
                image=settings.scanners.metasploit_image,
                command=command,
                detach=True,
                network=self.docker_network,
                remove=True,
                mem_limit="1g",
                cpu_period=100000,
                cpu_quota=50000,
            )
            
            try:
                result = container.wait(timeout=settings.scanners.scan_timeout)
                logs = container.logs().decode("utf-8")
                
                # Check for specific error patterns
                if "could not resolve" in logs.lower():
                    raise RuntimeError(f"Metasploit could not resolve target {target}. Check target validity.")
                elif "connection refused" in logs.lower() and "No response" in logs:
                    raise RuntimeError(f"Metasploit could not connect to target {target}. Target may be unreachable or ports filtered.")
                elif "no route to host" in logs.lower():
                    raise RuntimeError(f"Metasploit cannot reach target {target}. Check network connectivity.")
                elif "Error" in logs and "database" in logs.lower():
                    raise RuntimeError(f"Metasploit database error. This is likely a container configuration issue.")
                
                # Metasploit might return non-zero even on success, so we check logs for actual content
                if not logs.strip():
                    return "Metasploit scan completed but produced no output"
                
                return logs
                
            except Exception as e:
                try:
                    container.kill()
                except:
                    pass
                if "timeout" in str(e).lower():
                    raise RuntimeError(f"Metasploit scan timed out after {settings.scanners.scan_timeout} seconds")
                raise RuntimeError(f"Metasploit scan failed: {str(e)}")
                
        except Exception as e:
            if "Docker" in str(e):
                raise  # Re-raise Docker-specific errors
            raise RuntimeError(f"Metasploit scan setup failed: {str(e)}")
    
    async def _run_tshark(self, target: str, options: Dict[str, Any]) -> str:
        """Run Tshark network analysis"""
        capture_filter = options.get("filter", "")
        duration = options.get("duration", 60)  # seconds
        packet_count = options.get("packet_count", 1000)
        
        # Update progress
        if current_task:
            current_task.update_state(
                state="PROGRESS", 
                meta={
                    "step": "configuring_tshark",
                    "progress": 35,
                    "message": f"Configuring Tshark network capture"
                }
            )
        
        # Build tshark command
        command = f"tshark -i any -c {packet_count} -a duration:{duration}"
        if capture_filter:
            command += f" -f '{capture_filter}'"
        
        # Add analysis filters for interesting traffic
        command += " -Y 'tcp.flags.syn==1 or dns or http or icmp'"
        
        # Update progress
        if current_task:
            current_task.update_state(
                state="PROGRESS", 
                meta={
                    "step": "running_tshark_capture",
                    "progress": 45,
                    "message": f"Running Tshark capture: {command}"
                }
            )
        
        try:
            # Check if Docker is available
            try:
                import docker
                docker_client = docker.from_env()
                docker_client.ping()
            except Exception as docker_error:
                raise RuntimeError(f"Docker unavailable for Tshark scan: {docker_error}. Tshark requires Docker with network access.")
        
            container = self.docker_client.containers.run(
                image=settings.scanners.tshark_image,
                command=command,
                detach=True,
                network=self.docker_network,
                remove=True,
                mem_limit="512m",
                cap_add=["NET_ADMIN"],  # Required for packet capture
            )
            
            try:
                result = container.wait(timeout=settings.scanners.scan_timeout)
                logs = container.logs().decode("utf-8")
                
                # Check for specific error patterns
                if "permission denied" in logs.lower():
                    raise RuntimeError(f"Tshark permission denied. Container needs NET_ADMIN capability for packet capture.")
                elif "no such device" in logs.lower():
                    raise RuntimeError(f"Tshark could not find network interface. Check Docker network configuration.")
                elif "capture filter" in logs.lower() and "error" in logs.lower():
                    raise RuntimeError(f"Tshark capture filter error: {capture_filter}")
                elif result["StatusCode"] != 0 and not logs.strip():
                    raise RuntimeError(f"Tshark failed with exit code {result['StatusCode']} but produced no output")
                
                if not logs.strip():
                    return f"Tshark capture completed but no packets captured in {duration} seconds"
                
                return logs
                
            except Exception as e:
                try:
                    container.kill()
                except:
                    pass
                if "timeout" in str(e).lower():
                    raise RuntimeError(f"Tshark capture timed out after {settings.scanners.scan_timeout} seconds")
                raise RuntimeError(f"Tshark capture failed: {str(e)}")
                
        except Exception as e:
            if "Docker" in str(e):
                raise  # Re-raise Docker-specific errors
            raise RuntimeError(f"Tshark capture setup failed: {str(e)}")
    
    async def _run_openvas(self, target: str, options: Dict[str, Any]) -> str:
        """Run OpenVAS scan"""
        scan_config = options.get("config", "Full and fast")
        
        # OpenVAS requires more complex setup with GVM tools
        # This is a simplified implementation
        command = f"""
        gvm-cli --gmp-username admin --gmp-password admin socket --socketpath /run/gvmd/gvmd.sock --xml '
        <create_target>
            <name>{target}</name>
            <hosts>{target}</hosts>
        </create_target>'
        """
        
        container = self.docker_client.containers.run(
            image=settings.scanners.openvas_image,
            command=command,
            detach=True,
            network=self.docker_network,
            remove=True,
            mem_limit="2g",
        )
        
        try:
            result = container.wait(timeout=settings.scanners.scan_timeout)
            logs = container.logs().decode("utf-8")
            
            # OpenVAS setup is complex, for now return basic results
            return logs
            
        except Exception as e:
            try:
                container.kill()
            except:
                pass
            raise RuntimeError(f"OpenVAS scan failed: {str(e)}")
    
    async def _run_nikto(self, target: str, options: Dict[str, Any]) -> str:
        """Run Nikto web server scan"""
        scan_type = options.get("scan_type", "web_scan")
        check_outdated = options.get("check_outdated", True)
        scan_cgi = options.get("scan_cgi", True)
        
        # Update progress
        if current_task:
            current_task.update_state(
                state="PROGRESS", 
                meta={
                    "step": "configuring_nikto",
                    "progress": 35,
                    "message": f"Configuring Nikto scan for {target}"
                }
            )
        
        # Validate target is a URL or convert it
        if not target.startswith(('http://', 'https://')):
            raise ValueError(f"Nikto requires HTTP/HTTPS URL, got: {target}")
        
        # Build command
        command = f"nikto -h {target} -Format json"
        
        if check_outdated:
            command += " -Plugins outdated"
        if scan_cgi:
            command += " -Cgidirs all"
        
        # Update progress
        if current_task:
            current_task.update_state(
                state="PROGRESS", 
                meta={
                    "step": "running_nikto_scan",
                    "progress": 45,
                    "message": f"Running Nikto scan: {command}"
                }
            )
        
        try:
            # Check if Docker is available
            try:
                import docker
                docker_client = docker.from_env()
                docker_client.ping()
            except Exception as docker_error:
                raise RuntimeError(f"Docker unavailable for Nikto scan: {docker_error}. Nikto requires Docker to run.")
        
            container = self.docker_client.containers.run(
                image=getattr(settings.scanners, 'nikto_image', 'sullo/nikto'),
                command=command,
                detach=True,
                network=self.docker_network,
                remove=True,
                mem_limit="512m",
            )
            
            try:
                result = container.wait(timeout=settings.scanners.scan_timeout)
                logs = container.logs().decode("utf-8")
                
                # Check for specific error patterns
                if "could not resolve" in logs.lower():
                    raise RuntimeError(f"Nikto could not resolve hostname in {target}. Check target URL validity.")
                elif "connection refused" in logs.lower():
                    raise RuntimeError(f"Nikto could not connect to {target}. Web server may not be running.")
                elif "no web server found" in logs.lower():
                    raise RuntimeError(f"Nikto found no web server at {target}. Check if target is running a web service.")
                elif "timeout" in logs.lower() and "ERROR" in logs:
                    raise RuntimeError(f"Nikto timed out connecting to {target}")
                elif result["StatusCode"] != 0 and "No web server found" not in logs:
                    # Nikto returns non-zero on various conditions, check for actual errors
                    raise RuntimeError(f"Nikto scan failed with exit code {result['StatusCode']}: {logs[-300:]}")
                
                if not logs.strip():
                    return "Nikto scan completed but produced no output"
                
                return logs
                
            except Exception as e:
                try:
                    container.kill()
                except:
                    pass
                if "timeout" in str(e).lower():
                    raise RuntimeError(f"Nikto scan timed out after {settings.scanners.scan_timeout} seconds")
                raise RuntimeError(f"Nikto scan failed: {str(e)}")
                
        except Exception as e:
            if "Docker" in str(e):
                raise  # Re-raise Docker-specific errors
            raise RuntimeError(f"Nikto scan setup failed: {str(e)}")
    
    async def _transform_scan_results(self, tool: str, raw_output: str, 
                                    scan_id: str, target: str) -> List[Dict[str, Any]]:
        """Transform scan results to unified format"""
        if tool == "nmap":
            return nmap_to_unified(raw_output, scan_id, target)
        elif tool == "zap":
            return zap_to_unified(raw_output, scan_id, target)
        elif tool == "nuclei":
            return nuclei_to_unified(raw_output, scan_id, target)
        elif tool == "metasploit":
            return metasploit_to_unified(raw_output, scan_id, target)
        elif tool == "tshark":
            return tshark_to_unified(raw_output, scan_id, target)
        elif tool == "openvas":
            return openvas_to_unified(raw_output, scan_id, target)
        elif tool == "nikto":
            return nikto_to_unified(raw_output, scan_id, target)
        else:
            return []
    
    async def _store_vulnerabilities(self, session: AsyncSession, findings: List[Dict[str, Any]],
                                   asset_id: UUID, scan_id: UUID) -> int:
        """Store vulnerability findings with deduplication"""
        stored_count = 0
        
        for finding in findings:
            # Create deduplication hash
            dedup_data = f"{asset_id}:{finding.get('vuln_id', '')}:{finding.get('host', '')}:{finding.get('port', '')}"
            dedup_hash = hashlib.sha256(dedup_data.encode()).hexdigest()
            
            # Check if vulnerability already exists
            existing = await session.execute(
                select(Vulnerability).where(Vulnerability.dedup_hash == dedup_hash)
            )
            existing_vuln = existing.scalar_one_or_none()
            
            if existing_vuln:
                # Update last_seen timestamp
                existing_vuln.last_seen = datetime.utcnow()
                existing_vuln.scan_id = scan_id  # Update to latest scan
            else:
                # Create new vulnerability
                vulnerability = Vulnerability(
                    asset_id=asset_id,
                    scan_id=scan_id,
                    vuln_id=finding.get("vuln_id", ""),
                    name=finding.get("name", "Unknown"),
                    description=finding.get("description", ""),
                    severity=VulnerabilitySeverity(finding.get("severity", "info")),
                    host=finding.get("host", ""),
                    port=finding.get("port"),
                    service=finding.get("service"),
                    evidence=finding.get("evidence"),
                    dedup_hash=dedup_hash,
                )
                session.add(vulnerability)
                stored_count += 1
        
        await session.commit()
        return stored_count


# Initialize worker
worker = ScanWorker()


@celery_app.task(name="execute_scan", bind=True)
def execute_scan_task(self, scan_id: str):
    """Celery task to execute security scan"""
    # Run async function in event loop
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        result = loop.run_until_complete(worker.execute_scan(scan_id))
        return result
    finally:
        loop.close()


@celery_app.task(name="cancel_scan")
def cancel_scan_task(scan_id: str):
    """Cancel a running scan"""
    # Implementation for scan cancellation
    # This would involve stopping the Docker container and updating scan status
    return {"status": "cancelled", "scan_id": scan_id}
