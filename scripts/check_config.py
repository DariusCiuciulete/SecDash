"""
Configuration validation script for SecDash
"""
import os
import sys
import subprocess
import requests
from pathlib import Path

def check_python_version():
    """Check Python version"""
    version = sys.version_info
    if version.major == 3 and version.minor >= 8:
        print(f"✅ Python {version.major}.{version.minor}.{version.micro}")
        return True
    else:
        print(f"❌ Python {version.major}.{version.minor}.{version.micro} - Requires Python 3.8+")
        return False

def check_docker():
    """Check Docker availability"""
    try:
        result = subprocess.run(["docker", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ {result.stdout.strip()}")
            return True
        else:
            print("❌ Docker not available")
            return False
    except FileNotFoundError:
        print("❌ Docker not installed")
        return False

def check_docker_compose():
    """Check Docker Compose availability"""
    try:
        result = subprocess.run(["docker-compose", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ {result.stdout.strip()}")
            return True
        else:
            print("❌ Docker Compose not available")
            return False
    except FileNotFoundError:
        print("❌ Docker Compose not installed")
        return False

def check_npm():
    """Check Node.js/npm availability"""
    try:
        result = subprocess.run(["npm", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ npm {result.stdout.strip()}")
            return True
        else:
            print("❌ npm not available")
            return False
    except FileNotFoundError:
        print("⚠️ npm not installed (optional for frontend)")
        return False

def check_files():
    """Check required files"""
    base_dir = Path(__file__).parent
    required_files = [
        "backend/main.py",
        "backend/requirements.txt", 
        "backend/models.py",
        "backend/database.py",
        "docker-compose.yml",
        "test_comprehensive.py",
        "test_webapp.py"
    ]
    
    all_exist = True
    for file_path in required_files:
        full_path = base_dir / file_path
        if full_path.exists():
            print(f"✅ {file_path}")
        else:
            print(f"❌ {file_path} - Missing")
            all_exist = False
    
    return all_exist

def check_environment():
    """Check environment variables"""
    env_vars = [
        "DATABASE_URL",
        "REDIS_URL", 
        "CELERY_BROKER_URL"
    ]
    
    print("\n📋 Environment Variables:")
    all_set = True
    for var in env_vars:
        value = os.getenv(var)
        if value:
            # Hide sensitive parts
            display_value = value
            if "://" in value:
                parts = value.split("://")
                if len(parts) == 2:
                    scheme = parts[0]
                    rest = parts[1]
                    if "@" in rest:
                        auth_part, host_part = rest.split("@", 1)
                        display_value = f"{scheme}://***@{host_part}"
            print(f"✅ {var}={display_value}")
        else:
            print(f"⚠️ {var} - Not set (will use defaults)")
    
    return True  # Not critical for testing

def check_docker_images():
    """Check required Docker images"""
    required_images = [
        "postgres:15",
        "redis:7-alpine",
        "instrumentisto/nmap",
        "ghcr.io/zaproxy/zaproxy"
    ]
    
    print("\n🐳 Docker Images:")
    available = 0
    for image in required_images:
        try:
            result = subprocess.run(
                ["docker", "image", "inspect", image], 
                capture_output=True, 
                text=True
            )
            if result.returncode == 0:
                print(f"✅ {image}")
                available += 1
            else:
                print(f"⚠️ {image} - Not pulled yet")
        except:
            print(f"❌ {image} - Error checking")
    
    print(f"\n📊 {available}/{len(required_images)} images available")
    return available > 0

def main():
    """Main configuration check"""
    print("🔧 SecDash Configuration Check")
    print("=" * 50)
    
    checks = []
    
    print("\n🐍 System Requirements:")
    checks.append(check_python_version())
    checks.append(check_docker())
    checks.append(check_docker_compose())
    check_npm()  # Optional
    
    print("\n📁 Required Files:")
    checks.append(check_files())
    
    check_environment()
    check_docker_images()
    
    # Summary
    print("\n📋 Configuration Summary:")
    passed = sum(checks)
    total = len(checks)
    
    if passed == total:
        print(f"🎉 All critical checks passed ({passed}/{total})")
        print("\n🚀 Ready to run tests!")
        print("Run: python test_runner.py test")
        return True
    else:
        print(f"⚠️ {total - passed} critical checks failed ({passed}/{total})")
        print("\n🔧 Please fix the issues above before running tests")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
