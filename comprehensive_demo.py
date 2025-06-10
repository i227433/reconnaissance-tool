#!/usr/bin/env python3
"""
Comprehensive Demo Script for CyberRecon Tool
Demonstrates all reconnaissance capabilities with example.com
"""

import asyncio
import sys
import os
from pathlib import Path
import logging
from datetime import datetime

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from main import ReconTool
from utils.config import Config
from utils.logger import setup_logger


async def run_comprehensive_demo():
    """Run a comprehensive demonstration of all reconnaissance modules."""
    
    print("="*80)
    print("CYBERRECON - COMPREHENSIVE DEMONSTRATION")
    print("="*80)
    print(f"Target: example.com")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print("="*80)
    
    # Setup logging
    logger = setup_logger(log_level='INFO', log_file='logs/demo.log')
    
    # Initialize configuration
    config = Config('config/recon_config.json')
    
    # Initialize reconnaissance tool
    target = "example.com"
    recon_tool = ReconTool(target, config)
    
    print("\n🔍 PASSIVE RECONNAISSANCE")
    print("-" * 40)
    
    # 1. WHOIS Lookup
    print("\n1️⃣  WHOIS Lookup...")
    whois_result = await recon_tool.run_whois()
    if whois_result:
        print(f"   ✅ Domain: {whois_result.get('domain', 'N/A')}")
        print(f"   ✅ Registrar: {whois_result.get('registrar', 'N/A')}")
        print(f"   ✅ Creation Date: {whois_result.get('creation_date', 'N/A')}")
        print(f"   ✅ Expiration Date: {whois_result.get('expiration_date', 'N/A')}")
    
    # 2. DNS Enumeration
    print("\n2️⃣  DNS Enumeration...")
    dns_result = await recon_tool.run_dns()
    if dns_result:
        records = dns_result.get('records', {})
        print(f"   ✅ A Records: {len(records.get('A', []))}")
        print(f"   ✅ MX Records: {len(records.get('MX', []))}")
        print(f"   ✅ NS Records: {len(records.get('NS', []))}")
        print(f"   ✅ TXT Records: {len(records.get('TXT', []))}")
    
    # 3. Subdomain Discovery
    print("\n3️⃣  Subdomain Discovery...")
    subdomain_result = await recon_tool.run_subdomains()
    if subdomain_result:
        subdomains = subdomain_result.get('subdomains', [])
        active_subdomains = subdomain_result.get('active_subdomains', [])
        print(f"   ✅ Total Subdomains Found: {len(subdomains)}")
        print(f"   ✅ Active Subdomains: {len(active_subdomains)}")
        if active_subdomains:
            print(f"   📋 Active: {', '.join(active_subdomains[:5])}{'...' if len(active_subdomains) > 5 else ''}")
    
    print("\n🎯 ACTIVE RECONNAISSANCE")
    print("-" * 40)
    
    # Prepare targets for active reconnaissance
    targets = [target]
    if subdomain_result and 'active_subdomains' in subdomain_result:
        targets.extend(subdomain_result['active_subdomains'][:3])  # Limit for demo
    
    # 4. Port Scanning
    print("\n4️⃣  Port Scanning...")
    port_result = await recon_tool.run_port_scan(targets)
    if port_result:
        open_ports = []
        for host, data in port_result.items():
            if isinstance(data, dict) and 'open_ports' in data:
                open_ports.extend(data['open_ports'])
        print(f"   ✅ Targets Scanned: {len(targets)}")
        print(f"   ✅ Open Ports Found: {len(set(open_ports))}")
        if open_ports:
            unique_ports = sorted(set(open_ports))
            print(f"   📋 Ports: {', '.join(map(str, unique_ports[:10]))}{'...' if len(unique_ports) > 10 else ''}")
    
    # 5. Banner Grabbing
    print("\n5️⃣  Banner Grabbing...")
    banner_result = await recon_tool.run_banner_grab()
    if banner_result:
        banners_found = 0
        for host, data in banner_result.items():
            if isinstance(data, dict) and 'banners' in data:
                banners_found += len(data['banners'])
        print(f"   ✅ Banners Captured: {banners_found}")
    
    # 6. Technology Detection
    print("\n6️⃣  Technology Detection...")
    tech_result = await recon_tool.run_tech_detection(targets)
    if tech_result:
        technologies = []
        for host, data in tech_result.items():
            if isinstance(data, dict) and 'technologies' in data:
                technologies.extend(data['technologies'])
        print(f"   ✅ Technologies Detected: {len(set(technologies))}")
        if technologies:
            unique_techs = list(set(technologies))
            print(f"   📋 Technologies: {', '.join(unique_techs[:5])}{'...' if len(unique_techs) > 5 else ''}")
    
    print("\n📊 REPORT GENERATION")
    print("-" * 40)
    
    # Generate comprehensive report
    print("\n7️⃣  Generating Reports...")
    report_path = recon_tool.generate_report(
        output_format='both',
        output_file='comprehensive_demo'
    )
    
    print(f"   ✅ Text Report: {report_path}.txt")
    print(f"   ✅ HTML Report: {report_path}.html")
    print(f"   ✅ JSON Report: {report_path}.json")
    
    print("\n" + "="*80)
    print("DEMONSTRATION COMPLETED SUCCESSFULLY!")
    print("="*80)
    print(f"📁 Reports saved in: reports/")
    print(f"📝 Logs available in: logs/")
    print(f"🔧 Configuration: config/recon_config.json")
    print("="*80)
    
    return recon_tool.results


def display_usage_examples():
    """Display usage examples for the tool."""
    print("\n🚀 USAGE EXAMPLES")
    print("-" * 40)
    
    examples = [
        ("Basic scan", "python main.py example.com --all"),
        ("WHOIS only", "python main.py example.com --whois"),
        ("DNS + Subdomains", "python main.py example.com --dns --subdomains"),
        ("Port scan with custom range", "python main.py example.com --portscan --ports 1-1000"),
        ("HTML report only", "python main.py example.com --all --output-format html"),
        ("Verbose logging", "python main.py example.com --all --verbose --log-level DEBUG"),
        ("Custom output file", "python main.py example.com --all --output my_scan"),
        ("Quick scan (quiet)", "python main.py example.com --dns --portscan --quiet"),
    ]
    
    for i, (desc, cmd) in enumerate(examples, 1):
        print(f"\n{i}. {desc}:")
        print(f"   {cmd}")
    
    print("\n🐳 DOCKER EXAMPLES")
    print("-" * 20)
    
    docker_examples = [
        ("Build image", "docker build -t cyberrecon ."),
        ("Basic scan", "docker run --rm -v ${PWD}/reports:/app/reports cyberrecon example.com --all"),
        ("With custom config", "docker run --rm -v ${PWD}/config:/app/config -v ${PWD}/reports:/app/reports cyberrecon example.com --all"),
        ("Docker Compose", "docker-compose run --rm cyberrecon example.com --all"),
    ]
    
    for i, (desc, cmd) in enumerate(docker_examples, 1):
        print(f"\n{i}. {desc}:")
        print(f"   {cmd}")


async def main():
    """Main function to run the comprehensive demo."""
    try:
        # Ensure required directories exist
        os.makedirs('logs', exist_ok=True)
        os.makedirs('reports', exist_ok=True)
        os.makedirs('config', exist_ok=True)
        
        # Run comprehensive demo
        results = await run_comprehensive_demo()
        
        # Display usage examples
        display_usage_examples()
        
        return results
        
    except KeyboardInterrupt:
        print("\n\n❌ Demo interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Demo failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())