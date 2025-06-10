"""
Report Generation Module
Generates comprehensive reconnaissance reports in multiple formats.
"""

import os
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from jinja2 import Template
import base64
import socket
import re


class ReportGenerator:
    """Comprehensive report generation for reconnaissance results."""
    
    def __init__(self, config):
        """
        Initialize report generator.
        
        Args:
            config: Configuration object
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.output_dir = Path('reports')
        self.output_dir.mkdir(exist_ok=True)
    
    def generate(self, target: str, results: Dict[str, Any], 
                output_format: str = 'both', output_file: str = None) -> str:
        """
        Generate comprehensive reconnaissance report.
        
        Args:
            target (str): Target domain/IP
            results (dict): Combined results from all modules
            output_format (str): Format - 'text', 'html', or 'both'
            output_file (str): Output filename prefix
        
        Returns:
            Path to generated report(s)
        """
        self.logger.info(f"Generating {output_format} report for {target}")
        
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"recon_report_{target}_{timestamp}"
        
        generated_files = []
        
        try:
            # Generate text report
            if output_format in ['text', 'both']:
                text_path = self.output_dir / f"{output_file}.txt"
                self._generate_text_report(target, results, text_path)
                generated_files.append(str(text_path))
                self.logger.info(f"Text report generated: {text_path}")
            
            # Generate HTML report
            if output_format in ['html', 'both']:
                html_path = self.output_dir / f"{output_file}.html"
                self._generate_html_report(target, results, html_path)
                generated_files.append(str(html_path))
                self.logger.info(f"HTML report generated: {html_path}")
            
            # Generate JSON export
            json_path = self.output_dir / f"{output_file}.json"
            self._generate_json_export(target, results, json_path)
            generated_files.append(str(json_path))
            
            return generated_files[0] if len(generated_files) == 1 else str(self.output_dir / output_file)
            
        except Exception as e:
            self.logger.error(f"Report generation failed: {e}")
            raise
    
    def _generate_text_report(self, target: str, results: Dict[str, Any], output_path: Path):
        """Generate text format report."""
        report_content = []
        
        # Header
        report_content.append("=" * 80)
        report_content.append(f"RECONNAISSANCE REPORT FOR {target.upper()}")
        report_content.append("=" * 80)
        report_content.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_content.append("")
        
        # Executive Summary
        summary = self._generate_executive_summary(target, results)
        report_content.extend(self._format_executive_summary_text(summary))
        
        # WHOIS Information
        if 'whois' in results and results['whois']:
            report_content.extend(self._format_whois_text(results['whois']))
        
        # DNS Information
        if 'dns' in results and results['dns']:
            report_content.extend(self._format_dns_text(results['dns']))
        
        # Subdomain Information
        if 'subdomains' in results and results['subdomains']:
            report_content.extend(self._format_subdomains_text(results['subdomains']))
        
        # Port Scan Results
        if 'ports' in results and results['ports']:
            report_content.extend(self._format_ports_text(results['ports']))
        
        # Banner Information
        if 'banners' in results and results['banners']:
            report_content.extend(self._format_banners_text(results['banners']))
        
        # Technology Detection
        if 'technologies' in results and results['technologies']:
            report_content.extend(self._format_technologies_text(results['technologies']))
        
        # Security Analysis
        security_analysis = self._analyze_security_posture(results)
        report_content.extend(self._format_security_analysis_text(security_analysis))
        
        # Recommendations
        recommendations = self._generate_recommendations(results)
        report_content.extend(self._format_recommendations_text(recommendations))
        
        # Footer
        report_content.append("")
        report_content.append("=" * 80)
        report_content.append("END OF REPORT")
        report_content.append("=" * 80)
        
        # Write to file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(report_content))
    
    def _generate_html_report(self, target: str, results: Dict[str, Any], output_path: Path):
        """Generate HTML format report."""
        html_template = self._get_html_template()
        
        # Prepare data for template
        template_data = {
            'target': target,
            'generation_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'summary': self._generate_executive_summary(target, results),
            'whois': results.get('whois', {}),
            'dns': results.get('dns', {}),
            'subdomains': results.get('subdomains', {}),
            'ports': results.get('ports', {}),
            'banners': results.get('banners', {}),
            'technologies': results.get('technologies', {}),
            'security_analysis': self._analyze_security_posture(results),
            'recommendations': self._generate_recommendations(results),
            'charts_data': self._prepare_charts_data(results)
        }
        
        # Render template
        template = Template(html_template)
        html_content = template.render(**template_data)
        
        # Write to file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def _generate_json_export(self, target: str, results: Dict[str, Any], output_path: Path):
        """Generate JSON export of all results."""
        export_data = {
            'target': target,
            'generation_time': datetime.now().isoformat(),
            'summary': self._generate_executive_summary(target, results),
            'results': results,
            'security_analysis': self._analyze_security_posture(results),
            'recommendations': self._generate_recommendations(results)
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, default=str)
    
    def _generate_executive_summary(self, target: str, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary of reconnaissance results."""
        summary = {
            'target': target,
            'scope': self._determine_scope(results),
            'key_findings': [],
            'statistics': {
                'subdomains_found': 0,
                'active_subdomains': 0,
                'open_ports': 0,
                'services_identified': 0,
                'technologies_detected': 0,
                'security_issues': 0
            },
            'risk_level': 'Unknown',
            'notable_services': [],
            'technology_stack': []
        }
        
        # Subdomain statistics
        if 'subdomains' in results and results['subdomains']:
            subs = results['subdomains']
            summary['statistics']['subdomains_found'] = len(subs.get('subdomains', []))
            summary['statistics']['active_subdomains'] = len(subs.get('active_subdomains', []))
            
            if summary['statistics']['active_subdomains'] > 10:
                summary['key_findings'].append(f"Large subdomain footprint: {summary['statistics']['active_subdomains']} active subdomains")
        
        # Port scan statistics
        if 'ports' in results and results['ports']:
            ports = results['ports']
            total_open = 0
            services = set()
            
            for host_data in ports.get('results', {}).values():
                if isinstance(host_data, dict) and 'open_ports' in host_data:
                    open_ports = host_data['open_ports']
                    total_open += len(open_ports)
                    
                    for port_info in open_ports:
                        if 'service' in port_info:
                            services.add(port_info['service'])
            
            summary['statistics']['open_ports'] = total_open
            summary['statistics']['services_identified'] = len(services)
            summary['notable_services'] = list(services)[:10]  # Top 10
            
            if total_open > 20:
                summary['key_findings'].append(f"High number of open ports: {total_open}")
        
        # Technology detection statistics
        if 'technologies' in results and results['technologies']:
            tech = results['technologies']
            tech_count = 0
            stack = []
            
            for detection in tech.get('detections', {}).values():
                if isinstance(detection, dict):
                    technologies = detection.get('technologies', {})
                    tech_count += len(technologies)
                    
                    # Extract main technologies
                    for tech_name in technologies.keys():
                        if tech_name not in stack:
                            stack.append(tech_name)
            
            summary['statistics']['technologies_detected'] = tech_count
            summary['technology_stack'] = stack[:15]  # Top 15
        
        # Security analysis
        security_issues = self._count_security_issues(results)
        summary['statistics']['security_issues'] = security_issues
        summary['risk_level'] = self._assess_risk_level(results)
        
        if security_issues > 0:
            summary['key_findings'].append(f"Security issues identified: {security_issues}")
        
        # Notable findings
        if 'dns' in results and results['dns']:
            dns_data = results['dns']
            if dns_data.get('zone_transfer', {}).get('vulnerable'):
                summary['key_findings'].append("DNS Zone Transfer vulnerability detected")
        
        return summary
    
    def _analyze_security_posture(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze overall security posture."""
        analysis = {
            'overall_score': 0,
            'findings': [],
            'vulnerabilities': [],
            'good_practices': [],
            'recommendations_count': 0
        }
        
        score = 100  # Start with perfect score and deduct
        
        # DNS Security Analysis
        if 'dns' in results and results['dns']:
            dns_data = results['dns']
            
            # Check for zone transfer vulnerability
            if dns_data.get('zone_transfer', {}).get('vulnerable'):
                analysis['vulnerabilities'].append({
                    'severity': 'High',
                    'title': 'DNS Zone Transfer Vulnerability',
                    'description': 'Zone transfer is allowed, exposing internal DNS structure',
                    'impact': 'Information disclosure'
                })
                score -= 20
            
            # Check DNSSEC
            dns_security = dns_data.get('dns_security', {})
            if not dns_security.get('dnssec_enabled'):
                analysis['findings'].append({
                    'severity': 'Medium',
                    'title': 'DNSSEC Not Enabled',
                    'description': 'Domain does not use DNSSEC for DNS authentication',
                    'impact': 'DNS spoofing vulnerability'
                })
                score -= 10
            else:
                analysis['good_practices'].append('DNSSEC is properly configured')
        
        # Port Scan Security Analysis
        if 'ports' in results and results['ports']:
            ports_data = results['ports']
            
            risky_ports = [21, 22, 23, 25, 53, 110, 143, 993, 995, 1433, 3306, 3389, 5432]
            exposed_risky = []
            
            for host_data in ports_data.get('results', {}).values():
                if isinstance(host_data, dict) and 'open_ports' in host_data:
                    for port_info in host_data['open_ports']:
                        port = port_info.get('port')
                        if port in risky_ports:
                            exposed_risky.append(port)
            
            if exposed_risky:
                analysis['findings'].append({
                    'severity': 'Medium',
                    'title': 'Risky Ports Exposed',
                    'description': f'Potentially risky ports are exposed: {exposed_risky}',
                    'impact': 'Increased attack surface'
                })
                score -= len(exposed_risky) * 5
        
        # Technology Security Analysis
        if 'technologies' in results and results['technologies']:
            tech_data = results['technologies']
            
            for detection in tech_data.get('detections', {}).values():
                if isinstance(detection, dict):
                    # Check security headers
                    security_headers = detection.get('security_headers', {})
                    missing_headers = []
                    
                    critical_headers = ['X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection']
                    for header in critical_headers:
                        if header not in security_headers:
                            missing_headers.append(header)
                    
                    if missing_headers:
                        analysis['findings'].append({
                            'severity': 'Medium',
                            'title': 'Missing Security Headers',
                            'description': f'Critical security headers are missing: {missing_headers}',
                            'impact': 'XSS and clickjacking vulnerabilities'
                        })
                        score -= len(missing_headers) * 3
                    
                    # Check for good security practices
                    if 'Strict-Transport-Security' in security_headers:
                        analysis['good_practices'].append('HTTPS Strict Transport Security implemented')
                    
                    if 'Content-Security-Policy' in security_headers:
                        analysis['good_practices'].append('Content Security Policy implemented')
        
        # Banner Analysis
        if 'banners' in results and results['banners']:
            banner_data = results['banners']
            
            for service_banners in banner_data.get('banners', {}).values():
                if isinstance(service_banners, dict):
                    for banner_info in service_banners.values():
                        if isinstance(banner_info, dict):
                            version_info = banner_info.get('version_info', {})
                            if version_info and 'version' in version_info:
                                analysis['findings'].append({
                                    'severity': 'Low',
                                    'title': 'Version Information Disclosure',
                                    'description': f'Service version exposed: {version_info}',
                                    'impact': 'Information disclosure for targeted attacks'
                                })
                                score -= 2
        
        # Ensure score doesn't go below 0
        analysis['overall_score'] = max(0, score)
        analysis['recommendations_count'] = len(analysis['vulnerabilities']) + len(analysis['findings'])
        
        return analysis
    
    def _generate_recommendations(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate security recommendations based on findings."""
        recommendations = []
        
        # DNS recommendations
        if 'dns' in results and results['dns']:
            dns_data = results['dns']
            
            if dns_data.get('zone_transfer', {}).get('vulnerable'):
                recommendations.append({
                    'priority': 'High',
                    'category': 'DNS Security',
                    'title': 'Disable DNS Zone Transfer',
                    'description': 'Configure DNS servers to deny zone transfer requests from unauthorized sources',
                    'implementation': 'Update DNS server configuration to restrict zone transfers to authorized secondary servers only'
                })
            
            dns_security = dns_data.get('dns_security', {})
            if not dns_security.get('dnssec_enabled'):
                recommendations.append({
                    'priority': 'Medium',
                    'category': 'DNS Security',
                    'title': 'Enable DNSSEC',
                    'description': 'Implement DNSSEC to protect against DNS spoofing and cache poisoning attacks',
                    'implementation': 'Configure DNSSEC signing for the domain and ensure proper key management'
                })
        
        # Port security recommendations
        if 'ports' in results and results['ports']:
            risky_services = self._identify_risky_services(results['ports'])
            if risky_services:
                recommendations.append({
                    'priority': 'Medium',
                    'category': 'Network Security',
                    'title': 'Review Exposed Services',
                    'description': f'Review the necessity of exposing services: {risky_services}',
                    'implementation': 'Close unnecessary ports, implement proper access controls, and use VPN for administrative access'
                })
        
        # Web security recommendations
        if 'technologies' in results and results['technologies']:
            tech_data = results['technologies']
            
            missing_headers = []
            for detection in tech_data.get('detections', {}).values():
                if isinstance(detection, dict):
                    security_headers = detection.get('security_headers', {})
                    critical_headers = ['X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection', 'Strict-Transport-Security']
                    
                    for header in critical_headers:
                        if header not in security_headers and header not in missing_headers:
                            missing_headers.append(header)
            
            if missing_headers:
                recommendations.append({
                    'priority': 'Medium',
                    'category': 'Web Security',
                    'title': 'Implement Security Headers',
                    'description': f'Add missing security headers: {missing_headers}',
                    'implementation': 'Configure web server or application to include proper security headers in HTTP responses'
                })
        
        # General recommendations
        recommendations.extend([
            {
                'priority': 'Medium',
                'category': 'General Security',
                'title': 'Regular Security Assessments',
                'description': 'Conduct regular security assessments and penetration testing',
                'implementation': 'Schedule quarterly security assessments and implement continuous monitoring'
            },
            {
                'priority': 'Medium',
                'category': 'General Security',
                'title': 'Keep Software Updated',
                'description': 'Maintain current versions of all software and apply security patches promptly',
                'implementation': 'Implement automated patching where possible and maintain an inventory of all software versions'
            }
        ])
        
        return recommendations
    
    def _count_security_issues(self, results: Dict[str, Any]) -> int:
        """Count total security issues found."""
        issues = 0
        
        # DNS issues
        if 'dns' in results and results['dns']:
            dns_data = results['dns']
            if dns_data.get('zone_transfer', {}).get('vulnerable'):
                issues += 1
            if not dns_data.get('dns_security', {}).get('dnssec_enabled'):
                issues += 1
        
        # Technology issues
        if 'technologies' in results and results['technologies']:
            tech_data = results['technologies']
            for detection in tech_data.get('detections', {}).values():
                if isinstance(detection, dict):
                    security_headers = detection.get('security_headers', {})
                    critical_headers = ['X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection']
                    missing = sum(1 for header in critical_headers if header not in security_headers)
                    issues += missing
        
        return issues
    
    def _assess_risk_level(self, results: Dict[str, Any]) -> str:
        """Assess overall risk level based on findings."""
        risk_score = 0
        
        # High risk factors
        if 'dns' in results and results['dns']:
            if results['dns'].get('zone_transfer', {}).get('vulnerable'):
                risk_score += 3
        
        # Medium risk factors
        open_ports = 0
        if 'ports' in results and results['ports']:
            for host_data in results['ports'].get('results', {}).values():
                if isinstance(host_data, dict) and 'open_ports' in host_data:
                    open_ports += len(host_data['open_ports'])
        
        if open_ports > 20:
            risk_score += 2
        elif open_ports > 10:
            risk_score += 1
        
        # Determine risk level
        if risk_score >= 3:
            return 'High'
        elif risk_score >= 2:
            return 'Medium'
        elif risk_score >= 1:
            return 'Low'
        else:
            return 'Minimal'
    
    def _identify_risky_services(self, ports_data: Dict[str, Any]) -> List[str]:
        """Identify potentially risky exposed services."""
        risky_services = []
        risky_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            110: 'POP3',
            143: 'IMAP',
            1433: 'MSSQL',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL'
        }
        
        for host_data in ports_data.get('results', {}).values():
            if isinstance(host_data, dict) and 'open_ports' in host_data:
                for port_info in host_data['open_ports']:
                    port = port_info.get('port')
                    if port in risky_ports and risky_ports[port] not in risky_services:
                        risky_services.append(risky_ports[port])
        
        return risky_services
    
    def _determine_scope(self, results: Dict[str, Any]) -> str:
        """Determine reconnaissance scope from results."""
        components = []
        
        if 'whois' in results and results['whois']:
            components.append('WHOIS')
        if 'dns' in results and results['dns']:
            components.append('DNS')
        if 'subdomains' in results and results['subdomains']:
            components.append('Subdomain Enumeration')
        if 'ports' in results and results['ports']:
            components.append('Port Scanning')
        if 'banners' in results and results['banners']:
            components.append('Banner Grabbing')
        if 'technologies' in results and results['technologies']:
            components.append('Technology Detection')
        
        return ', '.join(components)
    
    def _prepare_charts_data(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare data for HTML charts."""
        charts = {
            'port_distribution': {},
            'technology_distribution': {},
            'subdomain_sources': {}
        }
        
        # Port distribution
        if 'ports' in results and results['ports']:
            port_counts = {}
            for host_data in results['ports'].get('results', {}).values():
                if isinstance(host_data, dict) and 'open_ports' in host_data:
                    for port_info in host_data['open_ports']:
                        service = port_info.get('service', 'Unknown')
                        port_counts[service] = port_counts.get(service, 0) + 1
            charts['port_distribution'] = port_counts
        
        # Technology distribution
        if 'technologies' in results and results['technologies']:
            tech_counts = {}
            for detection in results['technologies'].get('detections', {}).values():
                if isinstance(detection, dict):
                    for tech_name in detection.get('technologies', {}):
                        tech_counts[tech_name] = tech_counts.get(tech_name, 0) + 1
            charts['technology_distribution'] = tech_counts
        
        # Subdomain sources
        if 'subdomains' in results and results['subdomains']:
            sources = results['subdomains'].get('sources', {})
            source_counts = {k: len(v) for k, v in sources.items() if v}
            charts['subdomain_sources'] = source_counts
        
        return charts
    
    # Text formatting methods
    def _format_executive_summary_text(self, summary: Dict[str, Any]) -> List[str]:
        """Format executive summary for text report."""
        lines = ["EXECUTIVE SUMMARY", "=" * 40]
        
        stats = summary.get('statistics', {})
        lines.extend([
            f"Target: {summary.get('target', 'Unknown')}",
            f"Scope: {summary.get('scope', 'Unknown')}",
            f"Risk Level: {summary.get('risk_level', 'Unknown')}",
            "",
            "Key Statistics:",
            f"• Subdomains Found: {stats.get('subdomains_found', 0)}",
            f"• Active Subdomains: {stats.get('active_subdomains', 0)}",
            f"• Open Ports: {stats.get('open_ports', 0)}",
            f"• Services Identified: {stats.get('services_identified', 0)}",
            f"• Technologies Detected: {stats.get('technologies_detected', 0)}",
            f"• Security Issues: {stats.get('security_issues', 0)}",
            ""
        ])
        
        if summary.get('key_findings'):
            lines.extend(["Key Findings:"] + [f"• {finding}" for finding in summary['key_findings']] + [""])
        
        return lines
    
    def _format_whois_text(self, whois_data: Dict[str, Any]) -> List[str]:
        """Format WHOIS data for text report."""
        lines = ["WHOIS INFORMATION", "=" * 40]
        
        if 'error' in whois_data:
            lines.extend([f"Error: {whois_data['error']}", ""])
            return lines
        
        lines.extend([
            f"Domain: {whois_data.get('domain', 'Unknown')}",
            f"Registrar: {whois_data.get('registrar', 'Unknown')}",
            f"Creation Date: {whois_data.get('creation_date', 'Unknown')}",
            f"Expiration Date: {whois_data.get('expiration_date', 'Unknown')}",
            f"Updated Date: {whois_data.get('updated_date', 'Unknown')}",
            ""
        ])
        
        name_servers = whois_data.get('name_servers', [])
        if name_servers:
            lines.extend(["Name Servers:"] + [f"• {ns}" for ns in name_servers] + [""])
        
        return lines
    
    def _format_dns_text(self, dns_data: Dict[str, Any]) -> List[str]:
        """Format DNS data for text report."""
        lines = ["DNS INFORMATION", "=" * 40]
        
        if 'error' in dns_data:
            lines.extend([f"Error: {dns_data['error']}", ""])
            return lines
        
        # Basic info
        lines.extend([
            f"Domain: {dns_data.get('domain', 'Unknown')}",
            f"IP Addresses: {', '.join(dns_data.get('ip_addresses', []))}",
            ""
        ])
        
        # Mail servers
        mail_servers = dns_data.get('mail_servers', [])
        if mail_servers:
            lines.append("Mail Servers:")
            for mx in mail_servers:
                lines.append(f"• {mx.get('hostname', 'Unknown')} (Priority: {mx.get('priority', 'Unknown')})")
            lines.append("")
        
        # Security info
        dns_security = dns_data.get('dns_security', {})
        if dns_security:
            lines.extend([
                "DNS Security:",
                f"• DNSSEC Enabled: {'Yes' if dns_security.get('dnssec_enabled') else 'No'}",
                ""
            ])
        
        return lines
    
    def _format_subdomains_text(self, subdomain_data: Dict[str, Any]) -> List[str]:
        """Format subdomain data for text report."""
        lines = ["SUBDOMAIN ENUMERATION", "=" * 40]
        
        if 'error' in subdomain_data:
            lines.extend([f"Error: {subdomain_data['error']}", ""])
            return lines
        
        stats = subdomain_data.get('statistics', {})
        lines.extend([
            f"Total Subdomains Found: {stats.get('total_found', 0)}",
            f"Active Subdomains: {stats.get('total_active', 0)}",
            f"Success Rate: {stats.get('success_rate', 0):.1f}%",
            ""
        ])
        
        active_subdomains = subdomain_data.get('active_subdomains', [])
        if active_subdomains:
            lines.append("Active Subdomains:")
            for subdomain in active_subdomains[:20]:  # Limit to first 20
                lines.append(f"• {subdomain}")
            if len(active_subdomains) > 20:
                lines.append(f"• ... and {len(active_subdomains) - 20} more")
            lines.append("")
        
        return lines
    
    def _format_ports_text(self, ports_data: Dict[str, Any]) -> List[str]:
        """Format port scan data for text report."""
        lines = ["PORT SCAN RESULTS", "=" * 40]
        
        if 'error' in ports_data:
            lines.extend([f"Error: {ports_data['error']}", ""])
            return lines
        
        results = ports_data.get('results', {})
        total_hosts = len(results)
        total_open_ports = 0
        
        for host, host_data in results.items():
            if isinstance(host_data, dict) and 'open_ports' in host_data:
                open_ports = host_data['open_ports']
                total_open_ports += len(open_ports)
                
                lines.extend([
                    f"Host: {host}",
                    f"Open Ports: {len(open_ports)}",
                    ""
                ])
                
                for port_info in open_ports:
                    port = port_info.get('port', 'Unknown')
                    service = port_info.get('service', 'Unknown')
                    state = port_info.get('state', 'Unknown')
                    lines.append(f"  • {port}/{state} - {service}")
                
                lines.append("")
        
        lines.insert(2, f"Total Hosts Scanned: {total_hosts}")
        lines.insert(3, f"Total Open Ports: {total_open_ports}")
        lines.insert(4, "")
        
        return lines
    
    def _format_banners_text(self, banner_data: Dict[str, Any]) -> List[str]:
        """Format banner data for text report."""
        lines = ["BANNER INFORMATION", "=" * 40]
        
        if 'error' in banner_data:
            lines.extend([f"Error: {banner_data['error']}", ""])
            return lines
        
        banners = banner_data.get('banners', {})
        total_banners = sum(len(host_banners) for host_banners in banners.values() if isinstance(host_banners, dict))
        
        lines.extend([
            f"Total Banners Collected: {total_banners}",
            ""
        ])
        
        for host, host_banners in banners.items():
            if isinstance(host_banners, dict) and host_banners:
                lines.extend([f"Host: {host}", ""])
                
                for port, banner_info in host_banners.items():
                    if isinstance(banner_info, dict):
                        lines.append(f"  Port {port}:")
                        if 'banner' in banner_info:
                            banner_text = banner_info['banner'][:100]  # Truncate long banners
                            lines.append(f"    Banner: {banner_text}")
                        if 'service' in banner_info:
                            lines.append(f"    Service: {banner_info['service']}")
                        lines.append("")
        
        return lines
    
    def _format_technologies_text(self, tech_data: Dict[str, Any]) -> List[str]:
        """Format technology detection data for text report."""
        lines = ["TECHNOLOGY DETECTION", "=" * 40]
        
        if 'error' in tech_data:
            lines.extend([f"Error: {tech_data['error']}", ""])
            return lines
        
        detections = tech_data.get('detections', {})
        summary = tech_data.get('summary', {})
        
        lines.extend([
            f"Targets Analyzed: {summary.get('total_targets_analyzed', 0)}",
            f"Technologies Found: {len(summary.get('technologies_found', {}))}",
            ""
        ])
        
        # Technology summary
        tech_found = summary.get('technologies_found', {})
        if tech_found:
            lines.append("Technology Distribution:")
            for tech, count in sorted(tech_found.items(), key=lambda x: x[1], reverse=True)[:10]:
                lines.append(f"• {tech}: {count}")
            lines.append("")
        
        return lines
    
    def _format_security_analysis_text(self, security_analysis: Dict[str, Any]) -> List[str]:
        """Format security analysis for text report."""
        lines = ["SECURITY ANALYSIS", "=" * 40]
        
        score = security_analysis.get('overall_score', 0)
        lines.extend([
            f"Overall Security Score: {score}/100",
            ""
        ])
        
        # Vulnerabilities
        vulnerabilities = security_analysis.get('vulnerabilities', [])
        if vulnerabilities:
            lines.append("Vulnerabilities:")
            for vuln in vulnerabilities:
                lines.extend([
                    f"• {vuln.get('title', 'Unknown')} ({vuln.get('severity', 'Unknown')})",
                    f"  {vuln.get('description', 'No description')}",
                    ""
                ])
        
        # Findings
        findings = security_analysis.get('findings', [])
        if findings:
            lines.append("Security Findings:")
            for finding in findings:
                lines.extend([
                    f"• {finding.get('title', 'Unknown')} ({finding.get('severity', 'Unknown')})",
                    f"  {finding.get('description', 'No description')}",
                    ""
                ])
        
        # Good practices
        good_practices = security_analysis.get('good_practices', [])
        if good_practices:
            lines.append("Good Security Practices Identified:")
            for practice in good_practices:
                lines.append(f"✓ {practice}")
            lines.append("")
        
        if not vulnerabilities and not findings:
            lines.append("✓ No major security issues identified")
            lines.append("")
        
        return lines
    
    def _format_recommendations_text(self, recommendations: List[Dict[str, Any]]) -> List[str]:
        """Format recommendations for text report."""
        lines = ["RECOMMENDATIONS", "=" * 40]
        
        if not recommendations:
            lines.extend([
                "• Continue regular security assessments",
                "• Keep all software and systems updated",
                "• Monitor for new vulnerabilities",
                ""
            ])
            return lines
        
        # Group by priority
        high_priority = [r for r in recommendations if r.get('priority') == 'High']
        medium_priority = [r for r in recommendations if r.get('priority') == 'Medium']
        low_priority = [r for r in recommendations if r.get('priority') == 'Low']
        
        for priority_group, title in [(high_priority, "High Priority"), 
                                     (medium_priority, "Medium Priority"), 
                                     (low_priority, "Low Priority")]:
            if priority_group:
                lines.extend([f"{title} Recommendations:", ""])
                for rec in priority_group:
                    lines.extend([
                        f"• {rec.get('title', 'Unknown')}",
                        f"  Category: {rec.get('category', 'General')}",
                        f"  Description: {rec.get('description', 'No description')}",
                        f"  Implementation: {rec.get('implementation', 'See documentation')}",
                        ""
                    ])
        
        return lines
    
    def _get_html_template(self) -> str:
        """Get HTML template for report generation."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reconnaissance Report - {{ target }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; }
        .header h1 { color: #2c3e50; margin-bottom: 10px; }
        .meta-info { background: #ecf0f1; padding: 15px; border-radius: 5px; margin-bottom: 30px; }
        .section { margin-bottom: 30px; }
        .section h2 { color: #34495e; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
        .section h3 { color: #7f8c8d; margin-top: 20px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
        .stat-card { background: #f8f9fa; padding: 15px; border-radius: 5px; text-align: center; }
        .stat-number { font-size: 24px; font-weight: bold; color: #3498db; }
        .stat-label { color: #7f8c8d; font-size: 14px; }
        .risk-badge { padding: 5px 10px; border-radius: 3px; color: white; font-weight: bold; }
        .risk-high { background-color: #e74c3c; }
        .risk-medium { background-color: #f39c12; }
        .risk-low { background-color: #f1c40f; color: #2c3e50; }
        .risk-minimal { background-color: #27ae60; }
        .vulnerability { background: #fdf2f2; border-left: 4px solid #e74c3c; padding: 15px; margin: 10px 0; }
        .finding { background: #fef9e7; border-left: 4px solid #f39c12; padding: 15px; margin: 10px 0; }
        .good-practice { background: #eafaf1; border-left: 4px solid #27ae60; padding: 15px; margin: 10px 0; }
        .recommendation { background: #f8f9fa; border: 1px solid #dee2e6; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .priority-high { border-left: 4px solid #e74c3c; }
        .priority-medium { border-left: 4px solid #f39c12; }
        .priority-low { border-left: 4px solid #17a2b8; }
        ul { padding-left: 20px; }
        li { margin-bottom: 5px; }
        .code { background: #f4f4f4; padding: 2px 5px; border-radius: 3px; font-family: monospace; }
        .table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        .table th, .table td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        .table th { background-color: #f8f9fa; font-weight: bold; }
        .footer { text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #7f8c8d; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Reconnaissance Report</h1>
            <h2>{{ target }}</h2>
        </div>
        
        <div class="meta-info">
            <strong>Generated:</strong> {{ generation_time }}<br>
            <strong>Scope:</strong> {{ summary.scope }}<br>
            <strong>Risk Level:</strong> <span class="risk-badge risk-{{ summary.risk_level.lower() }}">{{ summary.risk_level }}</span>
        </div>
        
        <div class="section">
            <h2>Executive Summary</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">{{ summary.statistics.subdomains_found }}</div>
                    <div class="stat-label">Subdomains Found</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{{ summary.statistics.active_subdomains }}</div>
                    <div class="stat-label">Active Subdomains</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{{ summary.statistics.open_ports }}</div>
                    <div class="stat-label">Open Ports</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{{ summary.statistics.technologies_detected }}</div>
                    <div class="stat-label">Technologies</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{{ summary.statistics.security_issues }}</div>
                    <div class="stat-label">Security Issues</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{{ security_analysis.overall_score }}</div>
                    <div class="stat-label">Security Score</div>
                </div>
            </div>
            
            {% if summary.key_findings %}
            <h3>Key Findings</h3>
            <ul>
                {% for finding in summary.key_findings %}
                <li>{{ finding }}</li>
                {% endfor %}
            </ul>
            {% endif %}
        </div>
        
        {% if whois and not whois.error %}
        <div class="section">
            <h2>WHOIS Information</h2>
            <table class="table">
                <tr><th>Domain</th><td>{{ whois.domain }}</td></tr>
                <tr><th>Registrar</th><td>{{ whois.registrar or 'Unknown' }}</td></tr>
                <tr><th>Creation Date</th><td>{{ whois.creation_date or 'Unknown' }}</td></tr>
                <tr><th>Expiration Date</th><td>{{ whois.expiration_date or 'Unknown' }}</td></tr>
                {% if whois.name_servers %}
                <tr><th>Name Servers</th><td>{{ whois.name_servers | join(', ') }}</td></tr>
                {% endif %}
            </table>
        </div>
        {% endif %}
        
        {% if subdomains and not subdomains.error %}
        <div class="section">
            <h2>Subdomain Enumeration</h2>
            <p><strong>Total Found:</strong> {{ subdomains.statistics.total_found }}</p>
            <p><strong>Active:</strong> {{ subdomains.statistics.total_active }}</p>
            <p><strong>Success Rate:</strong> {{ "%.1f" | format(subdomains.statistics.success_rate) }}%</p>
            
            {% if subdomains.active_subdomains %}
            <h3>Active Subdomains</h3>
            <ul>
                {% for subdomain in subdomains.active_subdomains[:20] %}
                <li><span class="code">{{ subdomain }}</span></li>
                {% endfor %}
                {% if subdomains.active_subdomains | length > 20 %}
                <li><em>... and {{ subdomains.active_subdomains | length - 20 }} more</em></li>
                {% endif %}
            </ul>
            {% endif %}
        </div>
        {% endif %}
        
        {% if ports and not ports.error %}
        <div class="section">
            <h2>Port Scan Results</h2>
            {% for host, host_data in ports.results.items() %}
            {% if host_data.open_ports %}
            <h3>{{ host }}</h3>
            <table class="table">
                <thead>
                    <tr><th>Port</th><th>State</th><th>Service</th></tr>
                </thead>
                <tbody>
                    {% for port_info in host_data.open_ports %}
                    <tr>
                        <td>{{ port_info.port }}</td>
                        <td>{{ port_info.state }}</td>
                        <td>{{ port_info.service }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% endif %}
            {% endfor %}
        </div>
        {% endif %}
        
        {% if technologies and not technologies.error %}
        <div class="section">
            <h2>Technology Detection</h2>
            {% if technologies.summary %}
            <p><strong>Targets Analyzed:</strong> {{ technologies.summary.total_targets_analyzed }}</p>
            
            {% if technologies.summary.technologies_found %}
            <h3>Technology Distribution</h3>
            <ul>
                {% for tech, count in technologies.summary.technologies_found.items() %}
                <li>{{ tech }}: {{ count }}</li>
                {% endfor %}
            </ul>
            {% endif %}
            {% endif %}
        </div>
        {% endif %}
        
        <div class="section">
            <h2>Security Analysis</h2>
            <p><strong>Overall Security Score:</strong> {{ security_analysis.overall_score }}/100</p>
            
            {% if security_analysis.vulnerabilities %}
            <h3>Vulnerabilities</h3>
            {% for vuln in security_analysis.vulnerabilities %}
            <div class="vulnerability">
                <strong>{{ vuln.title }}</strong> ({{ vuln.severity }})<br>
                {{ vuln.description }}<br>
                <em>Impact:</em> {{ vuln.impact }}
            </div>
            {% endfor %}
            {% endif %}
            
            {% if security_analysis.findings %}
            <h3>Security Findings</h3>
            {% for finding in security_analysis.findings %}
            <div class="finding">
                <strong>{{ finding.title }}</strong> ({{ finding.severity }})<br>
                {{ finding.description }}<br>
                <em>Impact:</em> {{ finding.impact }}
            </div>
            {% endfor %}
            {% endif %}
            
            {% if security_analysis.good_practices %}
            <h3>Good Security Practices</h3>
            {% for practice in security_analysis.good_practices %}
            <div class="good-practice">✓ {{ practice }}</div>
            {% endfor %}
            {% endif %}
            
            {% if not security_analysis.vulnerabilities and not security_analysis.findings %}
            <div class="good-practice">✓ No major security issues identified</div>
            {% endif %}
        </div>
        
        <div class="section">
            <h2>Recommendations</h2>
            {% if recommendations %}
            {% for rec in recommendations %}
            <div class="recommendation priority-{{ rec.priority.lower() }}">
                <strong>{{ rec.title }}</strong> ({{ rec.priority }} Priority)<br>
                <em>Category:</em> {{ rec.category }}<br>
                <em>Description:</em> {{ rec.description }}<br>
                <em>Implementation:</em> {{ rec.implementation }}
            </div>
            {% endfor %}
            {% else %}
            <ul>
                <li>Continue regular security assessments</li>
                <li>Keep all software and systems updated</li>
                <li>Monitor for new vulnerabilities</li>
            </ul>
            {% endif %}
        </div>
        
        <div class="footer">
            <p>Report generated by CyberRecon Tool | {{ generation_time }}</p>
        </div>
    </div>
</body>
</html>"""