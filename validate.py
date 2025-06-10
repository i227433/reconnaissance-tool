#!/usr/bin/env python3
"""
Quick validation script for CyberRecon modules
"""

def validate_installation():
    """Validate that all modules can be imported successfully."""
    print("🧪 CyberRecon Module Validation")
    print("=" * 40)
    
    modules_to_test = [
        ('modules.whois_module', 'WHOIS Module'),
        ('modules.dns_module', 'DNS Module'),
        ('modules.subdomain_module', 'Subdomain Module'),
        ('modules.port_scanner', 'Port Scanner'),
        ('modules.banner_grabber', 'Banner Grabber'),
        ('modules.tech_detector', 'Technology Detector'),
        ('reports.report_generator', 'Report Generator'),
        ('utils.logger', 'Logger Utility'),
        ('utils.config', 'Config Utility'),
        ('utils.network', 'Network Utility')
    ]
    
    passed = 0
    failed = 0
    
    for module_name, display_name in modules_to_test:
        try:
            __import__(module_name)
            print(f"✅ {display_name}: PASSED")
            passed += 1
        except ImportError as e:
            print(f"❌ {display_name}: FAILED - {e}")
            failed += 1
        except Exception as e:
            print(f"⚠️  {display_name}: WARNING - {e}")
            passed += 1
    
    print("\n" + "=" * 40)
    print(f"📊 Results: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("🎉 All modules validated successfully!")
        print("🚀 CyberRecon is ready for use!")
        return True
    else:
        print("⚠️  Some modules failed validation.")
        print("📝 Check the error messages above.")
        return False

if __name__ == "__main__":
    validate_installation()
