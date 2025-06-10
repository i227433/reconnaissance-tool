#!/usr/bin/env python3
"""
CyberRecon - Advanced Reconnaissance Tool
A comprehensive reconnaissance tool for penetration testing and cybersecurity analysis.

Version: 1.0.0
License: MIT
"""

import argparse
import asyncio
import sys
import logging
import os
from datetime import datetime
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from modules.whois_module import WhoisModule
from modules.dns_module import DNSModule
from modules.subdomain_module import SubdomainModule
from modules.port_scanner import PortScanner
from modules.banner_grabber import BannerGrabber
from modules.tech_detector import TechnologyDetector
from reports.report_generator import ReportGenerator
from utils.logger import setup_logger
from utils.config import Config


class ReconTool:
    """Main reconnaissance tool class that orchestrates all modules."""
    
    def __init__(self, target: str, config: Config):
        """
        Initialize the reconnaissance tool.
        
        Args:
            target (str): Target domain or IP address
            config (Config): Configuration object
        """
        self.target = target
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.results = {}
        
        # Initialize modules
        self.whois_module = WhoisModule(config)
        self.dns_module = DNSModule(config)
        self.subdomain_module = SubdomainModule(config)
        self.port_scanner = PortScanner(config)
        self.banner_grabber = BannerGrabber(config)
        self.tech_detector = TechnologyDetector(config)
        self.report_generator = ReportGenerator(config)

    async def run_whois(self) -> dict:
        """Run WHOIS lookup on the target."""
        self.logger.info(f"Starting WHOIS lookup for {self.target}")
        try:
            result = await self.whois_module.lookup(self.target)
            self.results['whois'] = result
            return result
        except Exception as e:
            self.logger.error(f"WHOIS lookup failed: {e}")
            return {}

    async def run_dns(self) -> dict:
        """Run DNS enumeration on the target."""
        self.logger.info(f"Starting DNS enumeration for {self.target}")
        try:
            result = await self.dns_module.enumerate(self.target)
            self.results['dns'] = result
            return result
        except Exception as e:
            self.logger.error(f"DNS enumeration failed: {e}")
            return {}

    async def run_subdomains(self) -> dict:
        """Run subdomain enumeration on the target."""
        self.logger.info(f"Starting subdomain enumeration for {self.target}")
        try:
            result = await self.subdomain_module.enumerate(self.target)
            self.results['subdomains'] = result
            return result
        except Exception as e:
            self.logger.error(f"Subdomain enumeration failed: {e}")
            return {}

    async def run_port_scan(self, targets: list = None) -> dict:
        """Run port scanning on the target(s)."""
        if targets is None:
            targets = [self.target]
        
        self.logger.info(f"Starting port scan for {targets}")
        try:
            result = await self.port_scanner.scan(targets)
            self.results['ports'] = result
            return result
        except Exception as e:
            self.logger.error(f"Port scanning failed: {e}")
            return {}

    async def run_banner_grab(self, targets_ports: dict = None) -> dict:
        """Run banner grabbing on discovered open ports."""
        if targets_ports is None and 'ports' in self.results:
            targets_ports = self.results['ports']
        
        self.logger.info("Starting banner grabbing")
        try:
            result = await self.banner_grabber.grab_banners(targets_ports)
            self.results['banners'] = result
            return result
        except Exception as e:
            self.logger.error(f"Banner grabbing failed: {e}")
            return {}

    async def run_tech_detection(self, targets: list = None) -> dict:
        """Run technology detection on web services."""
        if targets is None:
            targets = [self.target]
        
        self.logger.info(f"Starting technology detection for {targets}")
        try:
            result = await self.tech_detector.detect(targets)
            self.results['technologies'] = result
            return result
        except Exception as e:
            self.logger.error(f"Technology detection failed: {e}")
            return {}

    async def run_all_modules(self) -> dict:
        """Run all reconnaissance modules."""
        self.logger.info(f"Starting comprehensive reconnaissance for {self.target}")
        
        # Run passive reconnaissance first
        await self.run_whois()
        await self.run_dns()
        subdomains_result = await self.run_subdomains()
        
        # Prepare targets for active reconnaissance
        targets = [self.target]
        if subdomains_result and 'active_subdomains' in subdomains_result:
            targets.extend(subdomains_result['active_subdomains'])
        
        # Run active reconnaissance
        await self.run_port_scan(targets)
        await self.run_banner_grab()
        await self.run_tech_detection(targets)
        
        return self.results

    def generate_report(self, output_format: str = 'both', output_file: str = None) -> str:
        """Generate comprehensive report of all results."""
        self.logger.info(f"Generating report in {output_format} format")
        
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"recon_report_{self.target}_{timestamp}"
        
        return self.report_generator.generate(
            target=self.target,
            results=self.results,
            output_format=output_format,
            output_file=output_file
        )


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    parser = argparse.ArgumentParser(
        description="Comprehensive Reconnaissance Tool for Penetration Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com --all
  %(prog)s example.com --whois --dns
  %(prog)s example.com --subdomains --portscan
  %(prog)s example.com --banners --tech
  %(prog)s example.com --all --output-format html --output report.html
        """
    )
    
    # Target argument
    parser.add_argument(
        'target',
        help='Target domain or IP address to reconnaissance'
    )
    
    # Module selection arguments
    parser.add_argument(
        '--whois',
        action='store_true',
        help='Perform WHOIS lookup'
    )
    
    parser.add_argument(
        '--dns',
        action='store_true',
        help='Perform DNS enumeration'
    )
    
    parser.add_argument(
        '--subdomains',
        action='store_true',
        help='Perform subdomain enumeration'
    )
    
    parser.add_argument(
        '--portscan',
        action='store_true',
        help='Perform port scanning'
    )
    
    parser.add_argument(
        '--banners',
        action='store_true',
        help='Perform banner grabbing'
    )
    
    parser.add_argument(
        '--tech',
        action='store_true',
        help='Perform technology detection'
    )
    
    parser.add_argument(
        '--all',
        action='store_true',
        help='Run all reconnaissance modules'
    )
    
    # Output options
    parser.add_argument(
        '--output-format',
        choices=['text', 'html', 'both'],
        default='both',
        help='Output format for reports (default: both)'
    )
    
    parser.add_argument(
        '--output',
        help='Output file name (without extension)'
    )
    
    # Logging options
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Set logging level (default: INFO)'
    )
    
    parser.add_argument(
        '--log-file',
        help='Log file path (default: logs/recon.log)'
    )
    
    # Configuration options
    parser.add_argument(
        '--config',
        help='Configuration file path'
    )
    
    parser.add_argument(
        '--threads',
        type=int,
        default=50,        help='Number of threads for concurrent operations (default: 50)'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=5,
        help='Timeout for network operations in seconds (default: 5)'
    )
    
    # Port scanning options
    parser.add_argument(
        '--ports',
        help='Port range for scanning (e.g., 1-1000, 22,80,443, top-100)'
    )
    
    parser.add_argument(
        '--scan-type',
        choices=['tcp', 'syn', 'udp'],
        default='tcp',
        help='Type of port scan to perform (default: tcp)'
    )
    
    # Subdomain enumeration options
    parser.add_argument(
        '--subdomain-wordlist',
        help='Custom wordlist file for subdomain enumeration'
    )
    
    parser.add_argument(
        '--api-keys',
        help='API keys configuration file for enhanced enumeration'
    )
    
    # Output options
    parser.add_argument(
        '--json',
        action='store_true',
        help='Also generate JSON output'
    )
    
    parser.add_argument(
        '--quiet',
        action='store_true',
        help='Suppress banner and progress messages'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    # Rate limiting
    parser.add_argument(
        '--rate-limit',
        type=float,
        default=1.0,
        help='Rate limit delay between requests in seconds (default: 1.0)'
    )
    
    return parser


async def main():
    """Main function to execute the reconnaissance tool."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Setup logging
    log_file = args.log_file or 'logs/recon.log'
    logger = setup_logger(log_level=args.log_level, log_file=log_file)
    
    # Load configuration
    config = Config(config_file=args.config)
    config.update_from_args(args)
    
    logger.info(f"Starting reconnaissance on target: {args.target}")
    
    try:
        # Initialize reconnaissance tool
        recon_tool = ReconTool(args.target, config)
        
        # Determine which modules to run
        if args.all:
            await recon_tool.run_all_modules()
        else:
            if args.whois:
                await recon_tool.run_whois()
            if args.dns:
                await recon_tool.run_dns()
            if args.subdomains:
                await recon_tool.run_subdomains()
            if args.portscan:
                await recon_tool.run_port_scan()
            if args.banners:
                await recon_tool.run_banner_grab()
            if args.tech:
                await recon_tool.run_tech_detection()
            
            # If no specific modules selected, run all
            if not any([args.whois, args.dns, args.subdomains, args.portscan, args.banners, args.tech]):
                logger.info("No specific modules selected, running all modules")
                await recon_tool.run_all_modules()
        
        # Generate report
        report_path = recon_tool.generate_report(
            output_format=args.output_format,
            output_file=args.output
        )
        
        logger.info(f"Reconnaissance completed successfully. Report saved to: {report_path}")
        print(f"\n[+] Reconnaissance completed successfully!")
        print(f"[+] Report saved to: {report_path}")
        
    except KeyboardInterrupt:
        logger.info("Reconnaissance interrupted by user")
        print("\n[!] Reconnaissance interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Reconnaissance failed: {e}")
        print(f"\n[!] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    # Ensure required directories exist
    os.makedirs('logs', exist_ok=True)
    os.makedirs('reports', exist_ok=True)
    os.makedirs('config', exist_ok=True)
    
    # Run the main function
    asyncio.run(main())
