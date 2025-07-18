"""
SecDash Testing Startup Script
This script starts all necessary services for comprehensive testing
"""
import subprocess
import time
import sys
import os
import threading
import requests
from pathlib import Path

class SecDashTestRunner:
    def __init__(self):
        self.processes = []
        self.base_dir = Path(__file__).parent
        self.backend_dir = self.base_dir / "backend"
        self.frontend_dir = self.base_dir / "frontend"
        
    def print_header(self, title: str):
        """Print formatted header"""
        print("\n" + "="*60)
        print(f" {title}")
        print("="*60)
    
    def run_command(self, cmd: str, cwd: str = None, background: bool = False):
        """Run a command"""
        print(f"🚀 Running: {cmd}")
        if background:
            process = subprocess.Popen(
                cmd, 
                shell=True, 
                cwd=cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            self.processes.append(process)
            return process
        else:
            result = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"❌ Command failed: {result.stderr}")
                return False
            else:
                print(f"✅ Command succeeded")
                return True
    
    def wait_for_service(self, url: str, timeout: int = 60):
        """Wait for a service to be available"""
        print(f"⏳ Waiting for {url} to be ready...")
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                response = requests.get(url, timeout=5)
                if response.status_code < 500:
                    print(f"✅ Service {url} is ready!")
                    return True
            except:
                pass
            time.sleep(2)
        
        print(f"❌ Service {url} not ready after {timeout} seconds")
        return False
    
    def start_infrastructure(self):
        """Start required infrastructure (Docker containers)"""
        self.print_header("Starting Infrastructure")
        
        print("🐳 Starting Docker containers...")
        success = self.run_command("docker-compose up -d postgres redis", cwd=self.base_dir)
        if not success:
            print("❌ Failed to start Docker containers")
            return False
        
        # Wait for services
        time.sleep(10)  # Give containers time to start
        print("✅ Infrastructure started")
        return True
    
    def start_backend(self):
        """Start the FastAPI backend"""
        self.print_header("Starting Backend")
        
        # Install dependencies if needed
        print("📦 Installing backend dependencies...")
        self.run_command("pip install -r requirements.txt", cwd=self.backend_dir)
        
        # Run database migrations
        print("🗄️ Running database migrations...")
        self.run_command("alembic upgrade head", cwd=self.backend_dir)
        
        # Start backend
        print("🌐 Starting FastAPI backend...")
        backend_process = self.run_command(
            "uvicorn main:app --reload --host 0.0.0.0 --port 8000",
            cwd=self.backend_dir,
            background=True
        )
        
        # Wait for backend to be ready
        if self.wait_for_service("http://localhost:8000/health"):
            print("✅ Backend started successfully")
            return True
        else:
            print("❌ Backend failed to start")
            return False
    
    def start_celery(self):
        """Start Celery worker"""
        self.print_header("Starting Celery Worker")
        
        print("⚙️ Starting Celery worker...")
        celery_process = self.run_command(
            "celery -A celery_app worker --loglevel=info --pool=solo",
            cwd=self.backend_dir,
            background=True
        )
        
        time.sleep(5)  # Give Celery time to start
        print("✅ Celery worker started")
        return True
    
    def start_frontend(self):
        """Start React frontend"""
        self.print_header("Starting Frontend")
        
        if not self.frontend_dir.exists():
            print("ℹ️ Frontend directory not found, skipping...")
            return True
        
        # Install dependencies
        print("📦 Installing frontend dependencies...")
        self.run_command("npm install", cwd=self.frontend_dir)
        
        # Start frontend
        print("⚛️ Starting React frontend...")
        frontend_process = self.run_command(
            "npm start",
            cwd=self.frontend_dir,
            background=True
        )
        
        time.sleep(10)  # Give React time to start
        print("✅ Frontend started")
        return True
    
    def start_test_webapp(self):
        """Start the vulnerable test web application"""
        self.print_header("Starting Test Web Application")
        
        print("🕷️ Starting vulnerable test web app...")
        webapp_process = self.run_command(
            f"python {self.base_dir}/test_webapp.py",
            background=True
        )
        
        # Wait for webapp to be ready
        if self.wait_for_service("http://127.0.0.1:8080"):
            print("✅ Test web application started")
            return True
        else:
            print("❌ Test web application failed to start")
            return False
    
    def setup_test_data(self):
        """Set up test data and profiles"""
        self.print_header("Setting Up Test Data")
        
        print("📋 Setting up scan profiles...")
        self.run_command(f"python {self.base_dir}/setup_profiles.py")
        
        print("✅ Test data setup completed")
    
    def run_tests(self):
        """Run comprehensive tests"""
        self.print_header("Running Comprehensive Tests")
        
        print("🧪 Running test suite...")
        success = self.run_command(f"python {self.base_dir}/test_comprehensive.py")
        
        if success:
            print("🎉 All tests passed!")
        else:
            print("⚠️ Some tests failed. Check output above.")
        
        return success
    
    def cleanup(self):
        """Clean up processes"""
        self.print_header("Cleanup")
        
        print("🧹 Stopping processes...")
        for process in self.processes:
            try:
                process.terminate()
                process.wait(timeout=5)
            except:
                process.kill()
        
        print("🐳 Stopping Docker containers...")
        self.run_command("docker-compose down", cwd=self.base_dir)
        
        print("✅ Cleanup completed")
    
    def run_full_test_suite(self):
        """Run the complete test suite"""
        try:
            self.print_header("SecDash Comprehensive Test Runner")
            print("🚀 Starting full test suite...")
            
            # Start all services
            if not self.start_infrastructure():
                return False
            
            if not self.start_backend():
                return False
            
            if not self.start_celery():
                return False
            
            # self.start_frontend()  # Optional
            
            if not self.start_test_webapp():
                return False
            
            self.setup_test_data()
            
            # Run tests
            test_success = self.run_tests()
            
            # Keep services running for manual testing
            if test_success:
                self.print_header("Services Ready for Manual Testing")
                print("🌐 Backend API: http://localhost:8000")
                print("📊 API Docs: http://localhost:8000/docs")
                print("🕷️ Test Web App: http://127.0.0.1:8080")
                print("⚛️ Frontend: http://localhost:3000 (if started)")
                print("\n⏸️ Press Ctrl+C to stop all services...")
                
                try:
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    print("\n🛑 Stopping services...")
            
            return test_success
            
        except KeyboardInterrupt:
            print("\n🛑 Interrupted by user")
            return False
        except Exception as e:
            print(f"❌ Error: {e}")
            return False
        finally:
            self.cleanup()

def main():
    """Main function"""
    if len(sys.argv) > 1:
        command = sys.argv[1]
        runner = SecDashTestRunner()
        
        if command == "test":
            success = runner.run_full_test_suite()
            sys.exit(0 if success else 1)
        elif command == "webapp":
            # Just start the test webapp
            runner.start_test_webapp()
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                runner.cleanup()
        elif command == "backend":
            # Just start backend services
            runner.start_infrastructure()
            runner.start_backend()
            runner.start_celery()
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                runner.cleanup()
        else:
            print("❌ Unknown command. Use: test, webapp, or backend")
            sys.exit(1)
    else:
        # Run full test suite by default
        runner = SecDashTestRunner()
        success = runner.run_full_test_suite()
        sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
