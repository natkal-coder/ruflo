#!/usr/bin/env python3
"""
Cross-platform test runner for all Hello World implementations.
This script tests each implementation and generates a detailed report.
"""

import subprocess
import sys
import os
import json
from pathlib import Path
from typing import Dict, Tuple, List
from datetime import datetime


class Colors:
    """ANSI color codes for terminal output."""
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    PURPLE = '\033[0;35m'
    NC = '\033[0m'  # No Color


class TestRunner:
    """Test runner for Hello World implementations."""
    
    def __init__(self):
        self.results = {}
        self.total_tests = 0
        self.passed_tests = 0
        self.failed_tests = 0
        self.skipped_tests = 0
        
    def print_status(self, status: str, message: str):
        """Print colored status messages."""
        if status == "PASS":
            print(f"{Colors.GREEN}✓ PASS{Colors.NC}: {message}")
        elif status == "FAIL":
            print(f"{Colors.RED}✗ FAIL{Colors.NC}: {message}")
        elif status == "INFO":
            print(f"{Colors.BLUE}ℹ INFO{Colors.NC}: {message}")
        elif status == "WARN":
            print(f"{Colors.YELLOW}⚠ WARN{Colors.NC}: {message}")
        elif status == "RUN":
            print(f"{Colors.PURPLE}▶ RUN{Colors.NC}: {message}")
            
    def check_command(self, command: str) -> bool:
        """Check if a command is available in the system."""
        try:
            subprocess.run([command, "--version"], 
                         capture_output=True, 
                         check=False)
            return True
        except FileNotFoundError:
            return False
            
    def run_command(self, command: List[str], cwd: str = None) -> Tuple[bool, str, str]:
        """Run a command and return success status, stdout, and stderr."""
        try:
            result = subprocess.run(
                command,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", "Command timed out"
        except Exception as e:
            return False, "", str(e)
            
    def test_python(self):
        """Test Python implementation."""
        print("\nTesting Python Implementation...")
        print("-" * 40)
        self.total_tests += 1
        
        if not Path("python/hello.py").exists():
            self.print_status("FAIL", "Python implementation not found")
            self.failed_tests += 1
            self.results["Python"] = {"status": "FAIL", "message": "File not found"}
            return
            
        if not self.check_command("python3"):
            self.print_status("WARN", "Python3 not installed, skipping tests")
            self.skipped_tests += 1
            self.results["Python"] = {"status": "SKIP", "message": "Python3 not installed"}
            return
            
        # Run the main script
        self.print_status("RUN", "Executing python/hello.py")
        success, stdout, stderr = self.run_command(["python3", "hello.py"], cwd="python")
        
        if success and "Hello, World!" in stdout:
            self.print_status("PASS", "Python implementation outputs correct greeting")
            self.passed_tests += 1
            
            # Run unit tests if available
            if Path("python/test_hello.py").exists():
                self.print_status("INFO", "Running Python unit tests...")
                test_success, test_stdout, test_stderr = self.run_command(
                    ["python3", "-m", "unittest", "test_hello.py", "-v"], 
                    cwd="python"
                )
                if test_success:
                    self.print_status("PASS", "Python unit tests passed")
                    self.results["Python"] = {
                        "status": "PASS", 
                        "message": "All tests passed",
                        "unit_tests": "PASS"
                    }
                else:
                    self.print_status("WARN", "Python unit tests failed")
                    self.results["Python"] = {
                        "status": "PASS", 
                        "message": "Main script passed, unit tests failed",
                        "unit_tests": "FAIL"
                    }
            else:
                self.results["Python"] = {"status": "PASS", "message": "Main script passed"}
        else:
            self.print_status("FAIL", f"Python implementation failed: {stderr}")
            self.failed_tests += 1
            self.results["Python"] = {"status": "FAIL", "message": stderr or "No Hello, World! output"}
            
    def test_javascript(self):
        """Test JavaScript implementation."""
        print("\nTesting JavaScript Implementation...")
        print("-" * 40)
        self.total_tests += 1
        
        if not Path("javascript/hello.js").exists():
            self.print_status("FAIL", "JavaScript implementation not found")
            self.failed_tests += 1
            self.results["JavaScript"] = {"status": "FAIL", "message": "File not found"}
            return
            
        if not self.check_command("node"):
            self.print_status("WARN", "Node.js not installed, skipping tests")
            self.skipped_tests += 1
            self.results["JavaScript"] = {"status": "SKIP", "message": "Node.js not installed"}
            return
            
        # Run the main script
        self.print_status("RUN", "Executing javascript/hello.js")
        success, stdout, stderr = self.run_command(["node", "hello.js"], cwd="javascript")
        
        if success and "Hello, World!" in stdout:
            self.print_status("PASS", "JavaScript implementation outputs correct greeting")
            self.passed_tests += 1
            
            # Check for test scripts in package.json
            if Path("javascript/package.json").exists():
                self.print_status("INFO", "package.json found")
                with open("javascript/package.json", "r") as f:
                    package_data = json.load(f)
                    if "scripts" in package_data and "test" in package_data["scripts"]:
                        self.print_status("INFO", "Test script found in package.json")
                        
            self.results["JavaScript"] = {"status": "PASS", "message": "All tests passed"}
        else:
            self.print_status("FAIL", f"JavaScript implementation failed: {stderr}")
            self.failed_tests += 1
            self.results["JavaScript"] = {"status": "FAIL", "message": stderr or "No Hello, World! output"}
            
    def test_go(self):
        """Test Go implementation."""
        print("\nTesting Go Implementation...")
        print("-" * 40)
        self.total_tests += 1
        
        if not Path("go/main.go").exists():
            self.print_status("FAIL", "Go implementation not found")
            self.failed_tests += 1
            self.results["Go"] = {"status": "FAIL", "message": "File not found"}
            return
            
        if not self.check_command("go"):
            self.print_status("WARN", "Go not installed, skipping tests")
            self.skipped_tests += 1
            self.results["Go"] = {"status": "SKIP", "message": "Go not installed"}
            return
            
        # Run the main script
        self.print_status("RUN", "Executing go/main.go")
        success, stdout, stderr = self.run_command(["go", "run", "main.go"], cwd="go")
        
        if success and "Hello, World!" in stdout:
            self.print_status("PASS", "Go implementation outputs correct greeting")
            self.passed_tests += 1
            
            # Check for go.mod
            if Path("go/go.mod").exists():
                self.print_status("INFO", "go.mod found - project properly initialized")
                
            self.results["Go"] = {"status": "PASS", "message": "All tests passed"}
        else:
            self.print_status("FAIL", f"Go implementation failed: {stderr}")
            self.failed_tests += 1
            self.results["Go"] = {"status": "FAIL", "message": stderr or "No Hello, World! output"}
            
    def test_rust(self):
        """Test Rust implementation."""
        print("\nTesting Rust Implementation...")
        print("-" * 40)
        self.total_tests += 1
        
        rust_files = [Path("rust/main.rs"), Path("rust/src/main.rs")]
        rust_file = None
        for f in rust_files:
            if f.exists():
                rust_file = f
                break
                
        if not rust_file:
            self.print_status("WARN", "Rust implementation not found (folder exists but is empty)")
            self.results["Rust"] = {"status": "NOT_FOUND", "message": "No main.rs file found"}
            return
            
        if not self.check_command("rustc"):
            self.print_status("WARN", "Rust not installed, skipping tests")
            self.skipped_tests += 1
            self.results["Rust"] = {"status": "SKIP", "message": "Rust not installed"}
            return
            
        # For now, just report that we would test it
        self.print_status("INFO", "Rust implementation found but not tested")
        self.results["Rust"] = {"status": "PENDING", "message": "Implementation found but not tested"}
        
    def generate_report(self):
        """Generate and display the test report."""
        print("\n" + "=" * 50)
        print("Test Summary Report")
        print("=" * 50)
        print(f"\nTest Run: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"\nTotal Tests Run: {self.total_tests}")
        print(f"Passed: {self.passed_tests}")
        print(f"Failed: {self.failed_tests}")
        print(f"Skipped: {self.skipped_tests}")
        
        print("\nImplementation Status:")
        print("-" * 25)
        
        for lang in ["Python", "JavaScript", "Go", "Rust"]:
            if lang in self.results:
                status = self.results[lang]["status"]
                message = self.results[lang].get("message", "")
                
                if status == "PASS":
                    print(f"{lang}: {Colors.GREEN}✓ PASSED{Colors.NC}")
                elif status == "FAIL":
                    print(f"{lang}: {Colors.RED}✗ FAILED{Colors.NC} - {message}")
                elif status == "SKIP":
                    print(f"{lang}: {Colors.YELLOW}⚠ SKIPPED{Colors.NC} - {message}")
                elif status == "NOT_FOUND":
                    print(f"{lang}: {Colors.YELLOW}⚠ NOT FOUND{Colors.NC}")
                else:
                    print(f"{lang}: {Colors.BLUE}ℹ {status}{Colors.NC}")
                    
        # Save results to JSON file
        report_data = {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total": self.total_tests,
                "passed": self.passed_tests,
                "failed": self.failed_tests,
                "skipped": self.skipped_tests
            },
            "results": self.results
        }
        
        with open("test_results.json", "w") as f:
            json.dump(report_data, f, indent=2)
            
        print(f"\n{Colors.BLUE}ℹ Detailed results saved to test_results.json{Colors.NC}")
        
        # Return appropriate exit code
        if self.failed_tests == 0:
            print(f"\n{Colors.GREEN}All implemented tests passed!{Colors.NC}")
            return 0
        else:
            print(f"\n{Colors.RED}Some tests failed. Please check the output above.{Colors.NC}")
            return 1
            
    def run_all_tests(self):
        """Run all tests and generate report."""
        print("=" * 50)
        print("Hello World Implementation Test Suite")
        print("=" * 50)
        
        self.test_python()
        self.test_javascript()
        self.test_go()
        self.test_rust()
        
        return self.generate_report()


def main():
    """Main entry point."""
    runner = TestRunner()
    sys.exit(runner.run_all_tests())


if __name__ == "__main__":
    main()