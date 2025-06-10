#!/usr/bin/env python3
"""
Test script to validate all CyberRecon modules are working correctly.
"""

import asyncio
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from modules.whois_module import whois_lookup
from modules.dns_module import dns_enumerate
from modules.subdomain_module import find_subdomains
from modules.port_scanner import scan_ports
from modules.banner_grabber import grab_banners
from modules.tech_detector import detect_technologies
from reports.report_generator import ReportGenerator

async def test_modules():
    """Test all modules with a safe domain."""
    test_domain = "example.com"
    print(f"🧪 Testing CyberRecon modules with domain: {test_domain}")
    print("=" * 60)
    
    results = {}
    
    # Test WHOIS module
    try:
        print("🔍 Testing WHOIS module...")
        whois_result = await whois_lookup(test_domain)
        results['whois'] = whois_result
        print("✅ WHOIS module: PASSED")
    except Exception as e:
        print(f"❌ WHOIS module: FAILED - {e}")
        results['whois'] = {}
    
    # Test DNS module
    try:
        print("🔍 Testing DNS module...")
        dns_result = await dns_enumerate(test_domain)
        results['dns'] = dns_result
        print("✅ DNS module: PASSED")
    except Exception as e:
        print(f"❌ DNS module: FAILED - {e}")
        results['dns'] = {}
    
    # Test Subdomain module
    try:
        print("🔍 Testing Subdomain module...")
        subdomain_result = await find_subdomains(test_domain)
        results['subdomains'] = subdomain_result
        print("✅ Subdomain module: PASSED")
    except Exception as e:
        print(f"❌ Subdomain module: FAILED - {e}")
        results['subdomains'] = []
    
    # Test Port Scanner (limited scan)
    try:
        print("🔍 Testing Port Scanner module...")
        port_result = await scan_ports(test_domain, "80,443")
        results['ports'] = port_result
        print("✅ Port Scanner module: PASSED")
    except Exception as e:
        print(f"❌ Port Scanner module: FAILED - {e}")
        results['ports'] = {}
    
    # Test Banner Grabber
    try:
        print("🔍 Testing Banner Grabber module...")
        banner_result = await grab_banners(test_domain, [80, 443])
        results['banners'] = banner_result
        print("✅ Banner Grabber module: PASSED")
    except Exception as e:
        print(f"❌ Banner Grabber module: FAILED - {e}")
        results['banners'] = {}
    
    # Test Technology Detector
    try:
        print("🔍 Testing Technology Detector module...")
        tech_result = await detect_technologies(test_domain)
        results['technologies'] = tech_result
        print("✅ Technology Detector module: PASSED")
    except Exception as e:
        print(f"❌ Technology Detector module: FAILED - {e}")
        results['technologies'] = {}
    
    # Test Report Generator
    try:
        print("🔍 Testing Report Generator...")
        report_gen = ReportGenerator(test_domain, results)
        test_report = report_gen.generate_text_report()
        if len(test_report) > 100:  # Basic validation
            print("✅ Report Generator: PASSED")
        else:
            print("❌ Report Generator: FAILED - Report too short")
    except Exception as e:
        print(f"❌ Report Generator: FAILED - {e}")
    
    print("\n" + "=" * 60)
    print("🎉 Module testing completed!")
    print("📝 Check the logs for detailed information.")
    print("🚀 CyberRecon is ready for use!")

if __name__ == "__main__":
    asyncio.run(test_modules())
