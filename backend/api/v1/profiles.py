"""
Scan profiles API endpoints
"""
from typing import Dict, List
from fastapi import APIRouter, HTTPException
from scan_profiles import SCAN_PROFILES, get_scan_profile, get_tool_profiles

router = APIRouter()

@router.get("/", summary="Get all scan profiles")
async def get_all_profiles():
    """Get all available scan profiles grouped by tool"""
    return SCAN_PROFILES

@router.get("/{tool}", summary="Get profiles for specific tool")
async def get_profiles_by_tool(tool: str):
    """Get all profiles for a specific scanning tool"""
    profiles = get_tool_profiles(tool)
    if not profiles:
        raise HTTPException(status_code=404, detail=f"No profiles found for tool: {tool}")
    return profiles

@router.get("/{tool}/{profile_name}", summary="Get specific profile")
async def get_specific_profile(tool: str, profile_name: str):
    """Get a specific scan profile"""
    profile = get_scan_profile(tool, profile_name)
    if not profile:
        raise HTTPException(
            status_code=404, 
            detail=f"Profile '{profile_name}' not found for tool '{tool}'"
        )
    return profile

@router.get("/tools/list", summary="List supported tools")
async def list_supported_tools():
    """List all supported scanning tools"""
    return {
        "tools": list(SCAN_PROFILES.keys()),
        "descriptions": {
            "nmap": "Network discovery and security auditing",
            "zap": "OWASP ZAP web application security scanner",
            "nuclei": "Vulnerability scanner based on templates",
            "openvas": "Comprehensive vulnerability assessment",
            "metasploit": "Penetration testing framework",
            "tshark": "Network protocol analyzer",
            "nikto": "Web server scanner"
        }
    }

@router.post("/validate", summary="Validate scan configuration")
async def validate_scan_config(config: dict):
    """Validate a scan configuration against available profiles"""
    tool = config.get("tool")
    profile_name = config.get("profile")
    
    if not tool:
        raise HTTPException(status_code=400, detail="Tool is required")
    
    if tool not in SCAN_PROFILES:
        raise HTTPException(status_code=400, detail=f"Unsupported tool: {tool}")
    
    if profile_name and profile_name not in SCAN_PROFILES[tool]:
        raise HTTPException(
            status_code=400, 
            detail=f"Profile '{profile_name}' not available for tool '{tool}'"
        )
    
    return {"valid": True, "message": "Configuration is valid"}
