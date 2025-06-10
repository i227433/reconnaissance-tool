#!/usr/bin/env python3
"""
Advanced Feature Showcase for CyberRecon Tool
Demonstrates advanced capabilities and use cases
"""

import asyncio
import sys
import os
from pathlib import Path
import json
from datetime import datetime

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from main import ReconTool
from utils.config import Config
from utils.logger import setup_logger


def print_banner():
    """Print the advanced feature showcase banner."""
    banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                    CYBERRECON - ADVANCED FEATURE SHOWCASE                   ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  🚀 Demonstrating Advanced Reconnaissance Capabilities                      ║
║  🔧 Enhanced CLI Options & Configuration Management                         ║
║  📊 Professional Reporting & Analysis                                       ║
║  🐳 Docker Deployment & Containerization                                    ║
║  🔒 Security Best Practices & Rate Limiting                                ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """
    print(banner)


async def showcase_advanced_scanning():
    """Demonstrate advanced scanning techniques."""
    print("\n🎯 ADVANCED SCANNING TECHNIQUES")
    print("="*80)
    
    # Setup configuration
    config = Config('config/recon_config.json')
    target = "example.com"
    
    print(f"\n1️⃣  Custom Port Range Scanning")
    print("-" * 40)
    print("Command: python main.py example.com --portscan --ports 80,443,8080 --scan-type tcp")
    
    print(f"\n2️⃣  Rate-Limited Subdomain Enumeration")
    print("-" * 40)
    print("Command: python main.py example.com --subdomains --rate-limit 2.0 --threads 10")
    
    print(f"\n3️⃣  Verbose DNS Analysis with Custom Nameservers")
    print("-" * 40)
    print("Command: python main.py example.com --dns --verbose --log-level DEBUG")
    
    print(f"\n4️⃣  Comprehensive Scan with Custom Output")
    print("-" * 40)
    print("Command: python main.py example.com --all --output-format html --json --output professional_report")


def showcase_configuration_features():
    """Demonstrate configuration management features."""
    print("\n⚙️ CONFIGURATION MANAGEMENT")
    print("="*80)
    
    # Load and display configuration
    config = Config('config/recon_config.json')
    
    print(f"\n📋 Current Configuration Overview:")
    print(f"   • Threads: {config.get('general.threads')}")
    print(f"   • Timeout: {config.get('general.timeout')} seconds")
    print(f"   • Rate Limit: {config.get('general.rate_limit_delay')} seconds")
    print(f"   • User Agent: {config.get('general.user_agent')[:50]}...")
    
    print(f"\n🔧 DNS Configuration:")
    nameservers = config.get('dns.nameservers', [])
    print(f"   • Nameservers: {', '.join(nameservers)}")
    record_types = config.get('dns.record_types', [])
    print(f"   • Record Types: {', '.join(record_types)}")
    
    print(f"\n🎯 Port Scanning Configuration:")
    common_ports = config.get('port_scanning.common_ports', [])
    print(f"   • Common Ports: {', '.join(map(str, common_ports[:10]))}... ({len(common_ports)} total)")
    print(f"   • Scan Type: {config.get('port_scanning.scan_type')}")
    print(f"   • Threads: {config.get('port_scanning.threads')}")
    
    print(f"\n🔍 API Configuration:")
    apis = config.get('apis', {})
    for api_name, api_url in apis.items():
        print(f"   • {api_name}: {api_url[:60]}...")


def showcase_reporting_capabilities():
    """Demonstrate reporting capabilities."""
    print("\n📊 REPORTING CAPABILITIES")
    print("="*80)
    
    # List available reports
    reports_dir = Path("reports")
    if reports_dir.exists():
        reports = list(reports_dir.glob("*.html")) + list(reports_dir.glob("*.txt")) + list(reports_dir.glob("*.json"))
        
        print(f"\n📁 Available Report Formats:")
        format_counts = {"html": 0, "txt": 0, "json": 0}
        for report in reports:
            if report.suffix[1:] in format_counts:
                format_counts[report.suffix[1:]] += 1
        
        for fmt, count in format_counts.items():
            print(f"   • {fmt.upper()}: {count} reports")
        
        print(f"\n📋 Recent Reports:")
        recent_reports = sorted(reports, key=lambda x: x.stat().st_mtime, reverse=True)[:5]
        for report in recent_reports:
            size_kb = report.stat().st_size / 1024
            mtime = datetime.fromtimestamp(report.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
            print(f"   • {report.name} ({size_kb:.1f} KB, {mtime})")


def showcase_docker_capabilities():
    """Demonstrate Docker deployment capabilities."""
    print("\n🐳 DOCKER DEPLOYMENT")
    print("="*80)
    
    print(f"\n🔨 Building Docker Image:")
    print("   docker build -t cyberrecon:latest .")
    
    print(f"\n🚀 Running Basic Scan:")
    print("   docker run --rm -v ${PWD}/reports:/app/reports cyberrecon example.com --all")
    
    print(f"\n⚙️ Custom Configuration:")
    print("   docker run --rm \\")
    print("     -v ${PWD}/config:/app/config:ro \\")
    print("     -v ${PWD}/reports:/app/reports \\")
    print("     cyberrecon example.com --all --config /app/config/custom.json")
    
    print(f"\n🔒 Privileged Scanning:")
    print("   docker run --rm --privileged \\")
    print("     -v ${PWD}/reports:/app/reports \\")
    print("     cyberrecon example.com --portscan --ports 1-65535")
    
    print(f"\n🎼 Docker Compose:")
    print("   docker-compose run --rm cyberrecon example.com --all")


def showcase_security_features():
    """Demonstrate security features and best practices."""
    print("\n🔒 SECURITY FEATURES")
    print("="*80)
    
    print(f"\n🛡️ Built-in Security Measures:")
    print("   • Rate limiting to prevent target overwhelming")
    print("   • Non-privileged Docker containers")
    print("   • Input validation and sanitization")
    print("   • Comprehensive audit logging")
    print("   • Configurable timeout and retry limits")
    
    print(f"\n⚖️ Ethical Usage Guidelines:")
    print("   • Only scan systems you own or have permission to test")
    print("   • Follow responsible disclosure practices")
    print("   • Comply with local laws and regulations")
    print("   • Use appropriate rate limiting for production systems")
    
    print(f"\n📝 Logging and Monitoring:")
    print("   • All operations are logged with timestamps")
    print("   • Different log levels for debugging and auditing")
    print("   • Structured logging for automated analysis")
    print("   • Performance metrics and execution timing")


def showcase_use_cases():
    """Demonstrate practical use cases."""
    print("\n💼 PRACTICAL USE CASES")
    print("="*80)
    
    use_cases = [
        {
            "name": "Penetration Testing Reconnaissance",
            "description": "Comprehensive information gathering phase",
            "command": "python main.py target.com --all --output-format html --output pentest_recon",
            "benefits": ["Complete target profiling", "Professional reporting", "Audit trail"]
        },
        {
            "name": "Bug Bounty Research",
            "description": "Subdomain discovery and technology stack analysis",
            "command": "python main.py target.com --subdomains --tech --rate-limit 2.0",
            "benefits": ["Respectful rate limiting", "Technology fingerprinting", "Subdomain enumeration"]
        },
        {
            "name": "Infrastructure Monitoring",
            "description": "Regular monitoring of your own infrastructure",
            "command": "python main.py yoursite.com --dns --portscan --json",
            "benefits": ["Automated monitoring", "JSON output for integration", "Change detection"]
        },
        {
            "name": "Security Assessment",
            "description": "Comprehensive security evaluation",
            "command": "python main.py client.com --all --verbose --threads 20",
            "benefits": ["Detailed analysis", "Professional documentation", "Risk assessment"]
        }
    ]
    
    for i, use_case in enumerate(use_cases, 1):
        print(f"\n{i}️⃣  {use_case['name']}")
        print(f"   Description: {use_case['description']}")
        print(f"   Command: {use_case['command']}")
        print(f"   Benefits:")
        for benefit in use_case['benefits']:
            print(f"     • {benefit}")


async def main():
    """Main function for the advanced showcase."""
    try:
        print_banner()
        
        # Ensure directories exist
        os.makedirs('logs', exist_ok=True)
        os.makedirs('reports', exist_ok=True)
        
        # Showcase different aspects
        await showcase_advanced_scanning()
        showcase_configuration_features()
        showcase_reporting_capabilities()
        showcase_docker_capabilities()
        showcase_security_features()
        showcase_use_cases()
        
        print("\n" + "="*80)
        print("🎉 ADVANCED FEATURE SHOWCASE COMPLETED")
        print("="*80)
        print("Your CyberRecon tool is ready for professional use!")
        print("Check the comprehensive documentation in README_ENHANCED.md")
        print("Run 'python comprehensive_validator.py' to verify system health")
        print("="*80)
        
    except Exception as e:
        print(f"\n❌ Showcase failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
