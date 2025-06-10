#!/usr/bin/env python3
"""
Comprehensive Validation Script for CyberRecon Tool
Tests all modules and validates functionality
"""

import asyncio
import sys
import os
from pathlib import Path
import logging
from datetime import datetime
import json

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from main import ReconTool
from utils.config import Config
from utils.logger import setup_logger


class ValidationResults:
    """Class to track validation results."""
    
    def __init__(self):
        self.tests = []
        self.passed = 0
        self.failed = 0
        self.errors = []
    
    def add_test(self, name: str, passed: bool, details: str = ""):
        """Add a test result."""
        self.tests.append({
            'name': name,
            'passed': passed,
            'details': details,
            'timestamp': datetime.now().isoformat()
        })
        if passed:
            self.passed += 1
        else:
            self.failed += 1
            self.errors.append(f"{name}: {details}")
    
    def print_summary(self):
        """Print validation summary."""
        print("\n" + "="*80)
        print("VALIDATION SUMMARY")
        print("="*80)
        print(f"Total Tests: {len(self.tests)}")
        print(f"✅ Passed: {self.passed}")
        print(f"❌ Failed: {self.failed}")
        print(f"Success Rate: {(self.passed / len(self.tests) * 100):.1f}%" if self.tests else "0%")
        
        if self.failed > 0:
            print(f"\n❌ FAILURES:")
            for error in self.errors:
                print(f"   • {error}")
        
        print("="*80)


async def validate_configuration():
    """Validate configuration system."""
    results = ValidationResults()
    
    print("\n🔧 CONFIGURATION VALIDATION")
    print("-" * 40)
    
    try:
        # Test default configuration
        config = Config()
        results.add_test("Default Configuration Load", True, "Successfully loaded default config")
        print("   ✅ Default configuration loaded")
        
        # Test configuration file loading
        if os.path.exists('config/recon_config.json'):
            config_file = Config('config/recon_config.json')
            results.add_test("Config File Load", True, "Successfully loaded config file")
            print("   ✅ Configuration file loaded")
        else:
            results.add_test("Config File Load", False, "Config file not found")
            print("   ❌ Configuration file not found")
        
        # Test configuration validation
        is_valid = config.validate()
        results.add_test("Configuration Validation", is_valid, "Config validation check")
        print(f"   {'✅' if is_valid else '❌'} Configuration validation")
        
        # Test getting configuration values
        timeout = config.get('general.timeout', 5)
        results.add_test("Config Value Retrieval", isinstance(timeout, (int, float)), f"Retrieved timeout: {timeout}")
        print(f"   ✅ Configuration value retrieval (timeout: {timeout})")
        
    except Exception as e:
        results.add_test("Configuration System", False, str(e))
        print(f"   ❌ Configuration error: {e}")
    
    return results


async def validate_modules():
    """Validate all reconnaissance modules."""
    results = ValidationResults()
    
    print("\n🔍 MODULE VALIDATION")
    print("-" * 40)
    
    try:
        # Initialize configuration and tool
        config = Config('config/recon_config.json' if os.path.exists('config/recon_config.json') else None)
        target = "example.com"
        recon_tool = ReconTool(target, config)
        
        # Test WHOIS module
        print("\n   Testing WHOIS module...")
        try:
            whois_result = await recon_tool.run_whois()
            success = whois_result is not None and 'domain' in whois_result
            results.add_test("WHOIS Module", success, f"Retrieved WHOIS data: {bool(whois_result)}")
            print(f"   {'✅' if success else '❌'} WHOIS module")
        except Exception as e:
            results.add_test("WHOIS Module", False, str(e))
            print(f"   ❌ WHOIS module failed: {e}")
        
        # Test DNS module
        print("   Testing DNS module...")
        try:
            dns_result = await recon_tool.run_dns()
            success = dns_result is not None and 'records' in dns_result
            results.add_test("DNS Module", success, f"Retrieved DNS records: {bool(dns_result)}")
            print(f"   {'✅' if success else '❌'} DNS module")
        except Exception as e:
            results.add_test("DNS Module", False, str(e))
            print(f"   ❌ DNS module failed: {e}")
        
        # Test Subdomain module
        print("   Testing Subdomain module...")
        try:
            subdomain_result = await recon_tool.run_subdomains()
            success = subdomain_result is not None
            results.add_test("Subdomain Module", success, f"Retrieved subdomains: {bool(subdomain_result)}")
            print(f"   {'✅' if success else '❌'} Subdomain module")
        except Exception as e:
            results.add_test("Subdomain Module", False, str(e))
            print(f"   ❌ Subdomain module failed: {e}")
        
        # Test Port Scanner module
        print("   Testing Port Scanner module...")
        try:
            port_result = await recon_tool.run_port_scan([target])
            success = port_result is not None
            results.add_test("Port Scanner Module", success, f"Port scan completed: {bool(port_result)}")
            print(f"   {'✅' if success else '❌'} Port Scanner module")
        except Exception as e:
            results.add_test("Port Scanner Module", False, str(e))
            print(f"   ❌ Port Scanner module failed: {e}")
        
        # Test Banner Grabber module
        print("   Testing Banner Grabber module...")
        try:
            banner_result = await recon_tool.run_banner_grab()
            success = banner_result is not None
            results.add_test("Banner Grabber Module", success, f"Banner grabbing completed: {bool(banner_result)}")
            print(f"   {'✅' if success else '❌'} Banner Grabber module")
        except Exception as e:
            results.add_test("Banner Grabber Module", False, str(e))
            print(f"   ❌ Banner Grabber module failed: {e}")
        
        # Test Technology Detector module
        print("   Testing Technology Detector module...")
        try:
            tech_result = await recon_tool.run_tech_detection([target])
            success = tech_result is not None
            results.add_test("Technology Detector Module", success, f"Tech detection completed: {bool(tech_result)}")
            print(f"   {'✅' if success else '❌'} Technology Detector module")
        except Exception as e:
            results.add_test("Technology Detector Module", False, str(e))
            print(f"   ❌ Technology Detector module failed: {e}")
        
    except Exception as e:
        results.add_test("Module Initialization", False, str(e))
        print(f"   ❌ Module initialization failed: {e}")
    
    return results


async def validate_reporting():
    """Validate report generation functionality."""
    results = ValidationResults()
    
    print("\n📊 REPORTING VALIDATION")
    print("-" * 40)
    
    try:
        # Initialize and run basic scan
        config = Config('config/recon_config.json' if os.path.exists('config/recon_config.json') else None)
        target = "example.com"
        recon_tool = ReconTool(target, config)
        
        # Run a quick scan to get some data
        await recon_tool.run_whois()
        
        # Test text report generation
        print("   Testing text report generation...")
        try:
            report_path = recon_tool.generate_report(output_format='text', output_file='validation_test')
            text_report_exists = os.path.exists(f"{report_path}.txt")
            results.add_test("Text Report Generation", text_report_exists, f"Report path: {report_path}.txt")
            print(f"   {'✅' if text_report_exists else '❌'} Text report generation")
        except Exception as e:
            results.add_test("Text Report Generation", False, str(e))
            print(f"   ❌ Text report generation failed: {e}")
        
        # Test HTML report generation
        print("   Testing HTML report generation...")
        try:
            report_path = recon_tool.generate_report(output_format='html', output_file='validation_test_html')
            html_report_exists = os.path.exists(f"{report_path}.html")
            results.add_test("HTML Report Generation", html_report_exists, f"Report path: {report_path}.html")
            print(f"   {'✅' if html_report_exists else '❌'} HTML report generation")
        except Exception as e:
            results.add_test("HTML Report Generation", False, str(e))
            print(f"   ❌ HTML report generation failed: {e}")
        
        # Test JSON report generation
        print("   Testing JSON report generation...")
        try:
            report_path = recon_tool.generate_report(output_format='both', output_file='validation_test_json')
            json_report_exists = os.path.exists(f"{report_path}.json")
            results.add_test("JSON Report Generation", json_report_exists, f"Report path: {report_path}.json")
            print(f"   {'✅' if json_report_exists else '❌'} JSON report generation")
            
            # Validate JSON content
            if json_report_exists:
                with open(f"{report_path}.json", 'r') as f:
                    json_data = json.load(f)
                    json_valid = isinstance(json_data, dict) and 'target' in json_data
                    results.add_test("JSON Report Content", json_valid, "JSON structure validation")
                    print(f"   {'✅' if json_valid else '❌'} JSON report content validation")
        except Exception as e:
            results.add_test("JSON Report Generation", False, str(e))
            print(f"   ❌ JSON report generation failed: {e}")
        
    except Exception as e:
        results.add_test("Report System", False, str(e))
        print(f"   ❌ Report system error: {e}")
    
    return results


async def validate_dependencies():
    """Validate required dependencies."""
    results = ValidationResults()
    
    print("\n📦 DEPENDENCY VALIDATION")
    print("-" * 40)
    
    # Required Python modules
    required_modules = [
        'requests', 'aiohttp', 'dns', 'whois', 'bs4', 
        'nmap', 'colorama', 'tabulate', 'jinja2'
    ]
    
    for module in required_modules:
        try:
            if module == 'dns':
                import dns.resolver
            elif module == 'bs4':
                import bs4
            else:
                __import__(module)
            results.add_test(f"Module: {module}", True, f"Successfully imported {module}")
            print(f"   ✅ {module}")
        except ImportError as e:
            results.add_test(f"Module: {module}", False, str(e))
            print(f"   ❌ {module} - {e}")
    
    # Check external tools
    external_tools = ['nmap']
    for tool in external_tools:
        try:
            import subprocess
            result = subprocess.run([tool, '--version'], capture_output=True, text=True, timeout=10)
            success = result.returncode == 0
            results.add_test(f"External Tool: {tool}", success, f"Available: {success}")
            print(f"   {'✅' if success else '❌'} {tool}")
        except Exception as e:
            results.add_test(f"External Tool: {tool}", False, str(e))
            print(f"   ❌ {tool} - {e}")
    
    return results


async def main():
    """Main validation function."""
    print("="*80)
    print("CYBERRECON - COMPREHENSIVE VALIDATION")
    print("="*80)
    print(f"Timestamp: {datetime.now().isoformat()}")
    print("="*80)
    
    # Ensure required directories exist
    os.makedirs('logs', exist_ok=True)
    os.makedirs('reports', exist_ok=True)
    os.makedirs('config', exist_ok=True)
    
    # Run all validations
    all_results = ValidationResults()
    
    # Validate dependencies first
    dep_results = await validate_dependencies()
    all_results.tests.extend(dep_results.tests)
    all_results.passed += dep_results.passed
    all_results.failed += dep_results.failed
    all_results.errors.extend(dep_results.errors)
    
    # Validate configuration
    config_results = await validate_configuration()
    all_results.tests.extend(config_results.tests)
    all_results.passed += config_results.passed
    all_results.failed += config_results.failed
    all_results.errors.extend(config_results.errors)
    
    # Validate modules
    module_results = await validate_modules()
    all_results.tests.extend(module_results.tests)
    all_results.passed += module_results.passed
    all_results.failed += module_results.failed
    all_results.errors.extend(module_results.errors)
    
    # Validate reporting
    report_results = await validate_reporting()
    all_results.tests.extend(report_results.tests)
    all_results.passed += report_results.passed
    all_results.failed += report_results.failed
    all_results.errors.extend(report_results.errors)
    
    # Print overall summary
    all_results.print_summary()
    
    # Save validation results
    validation_report = {
        'timestamp': datetime.now().isoformat(),
        'summary': {
            'total_tests': len(all_results.tests),
            'passed': all_results.passed,
            'failed': all_results.failed,
            'success_rate': (all_results.passed / len(all_results.tests) * 100) if all_results.tests else 0
        },
        'tests': all_results.tests,
        'errors': all_results.errors
    }
    
    with open('reports/validation_results.json', 'w') as f:
        json.dump(validation_report, f, indent=2)
    
    print(f"\n📁 Validation results saved to: reports/validation_results.json")
    
    # Return appropriate exit code
    return 0 if all_results.failed == 0 else 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)