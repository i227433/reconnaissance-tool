"""
Technology Detection Module
Identifies web technologies, frameworks, and server software.
"""

import asyncio
import json
import re
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional, Set
from urllib.parse import urljoin, urlparse
from utils.logger import log_performance
from utils.network import NetworkUtils


class TechnologyDetector:
    """Technology detection functionality for web service analysis."""
    
    def __init__(self, config):
        """
        Initialize technology detector.
        
        Args:
            config: Configuration object
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.network_utils = NetworkUtils(config)
        
        # Technology fingerprints
        self.tech_fingerprints = self._load_technology_fingerprints()
        
    def _load_technology_fingerprints(self) -> Dict[str, Any]:
        """
        Load technology detection fingerprints.
        
        Returns:
            Dictionary of technology fingerprints
        """
        return {
            'headers': {
                'server': {
                    'Apache': [r'Apache/[\d.]+', r'Apache'],
                    'Nginx': [r'nginx/[\d.]+', r'nginx'],
                    'IIS': [r'Microsoft-IIS/[\d.]+', r'IIS'],
                    'Cloudflare': [r'cloudflare'],
                    'LiteSpeed': [r'LiteSpeed'],
                    'OpenResty': [r'openresty/[\d.]+']
                },
                'x-powered-by': {
                    'PHP': [r'PHP/[\d.]+'],
                    'ASP.NET': [r'ASP\.NET'],
                    'Express': [r'Express'],
                    'Django': [r'Django/[\d.]+'],
                    'Flask': [r'Flask'],
                    'Rails': [r'Phusion Passenger']
                },
                'x-generator': {
                    'WordPress': [r'WordPress [\d.]+'],
                    'Drupal': [r'Drupal [\d.]+'],
                    'Joomla': [r'Joomla! [\d.]+']
                },
                'x-frame-options': {
                    'Security Headers': [r'DENY', r'SAMEORIGIN']
                }
            },
            'html_content': {
                'WordPress': [
                    r'wp-content/',
                    r'wp-includes/',
                    r'wordpress',
                    r'<!-- This site is optimized with the Yoast SEO plugin'
                ],
                'Drupal': [
                    r'Drupal\.settings',
                    r'sites/default/files',
                    r'misc/drupal\.js'
                ],
                'Joomla': [
                    r'Joomla!',
                    r'joomla',
                    r'option=com_'
                ],
                'React': [
                    r'React',
                    r'react\.js',
                    r'__REACT_DEVTOOLS_GLOBAL_HOOK__'
                ],
                'Angular': [
                    r'ng-app',
                    r'angular\.js',
                    r'ng-controller'
                ],
                'Vue.js': [
                    r'Vue\.js',
                    r'vue\.js',
                    r'v-if',
                    r'v-for'
                ],
                'jQuery': [
                    r'jquery',
                    r'jQuery'
                ],
                'Bootstrap': [
                    r'bootstrap',
                    r'Bootstrap'
                ],
                'Laravel': [
                    r'laravel_session',
                    r'Laravel'
                ],
                'Symfony': [
                    r'Symfony',
                    r'symfony'
                ],
                'CodeIgniter': [
                    r'CodeIgniter',
                    r'ci_session'
                ],
                'Spring': [
                    r'Spring Framework',
                    r'JSESSIONID'
                ],
                'Django': [
                    r'django',
                    r'csrfmiddlewaretoken'
                ],
                'Flask': [
                    r'Flask',
                    r'session='
                ],
                'Express.js': [
                    r'Express',
                    r'connect\.sid'
                ]
            },
            'cookies': {
                'PHP': ['PHPSESSID'],
                'ASP.NET': ['ASP.NET_SessionId', 'ASPSESSIONID'],
                'JSP': ['JSESSIONID'],
                'ColdFusion': ['CFID', 'CFTOKEN'],
                'Django': ['sessionid', 'csrftoken'],
                'Laravel': ['laravel_session'],
                'WordPress': ['wordpress_', 'wp-settings-'],
                'Drupal': ['SESS', 'SSESS']
            },
            'script_sources': {
                'Google Analytics': [r'google-analytics\.com', r'googletagmanager\.com'],
                'jQuery': [r'jquery.*\.js'],
                'Bootstrap': [r'bootstrap.*\.js', r'bootstrap.*\.css'],
                'Angular': [r'angular.*\.js'],
                'React': [r'react.*\.js'],
                'Vue.js': [r'vue.*\.js'],
                'Cloudflare': [r'cloudflare\.com'],
                'Font Awesome': [r'fontawesome', r'fa-'],
                'Google Fonts': [r'fonts\.googleapis\.com']
            },
            'meta_tags': {
                'WordPress': [r'WordPress', r'wp-'],
                'Drupal': [r'Drupal'],
                'Joomla': [r'Joomla'],
                'Shopify': [r'Shopify'],
                'Magento': [r'Magento'],
                'PrestaShop': [r'PrestaShop']
            }
        }
    
    @log_performance
    async def detect(self, targets: List[str]) -> Dict[str, Any]:
        """
        Detect technologies for web targets.
        
        Args:
            targets (list): List of target hosts/domains
        
        Returns:
            Technology detection results
        """
        self.logger.info(f"Starting technology detection for {len(targets)} targets")
        
        result = {
            'timestamp': datetime.now().isoformat(),
            'targets': targets,
            'detections': {},
            'summary': {},
            'security_analysis': {}
        }
        
        try:
            # Create detection tasks for all targets
            detection_tasks = []
            for target in targets:
                # Try both HTTP and HTTPS
                for protocol in ['http', 'https']:
                    for port in [80, 443, 8080, 8443]:
                        if (protocol == 'http' and port in [80, 8080]) or \
                           (protocol == 'https' and port in [443, 8443]):
                            url = f"{protocol}://{target}"
                            if port not in [80, 443]:
                                url += f":{port}"
                            
                            task = asyncio.create_task(self._detect_single_target(url))
                            detection_tasks.append(task)
            
            # Execute detection tasks
            detection_results = await asyncio.gather(*detection_tasks, return_exceptions=True)
            
            # Process results
            for detection_result in detection_results:
                if isinstance(detection_result, dict) and not isinstance(detection_result, Exception):
                    if detection_result.get('accessible'):
                        target_key = detection_result['url']
                        result['detections'][target_key] = detection_result
            
            # Generate summary and analysis
            result['summary'] = self._generate_detection_summary(result['detections'])
            result['security_analysis'] = self._analyze_security_technologies(result['detections'])
            
            self.logger.info(f"Technology detection completed. Analyzed {len(result['detections'])} accessible targets")
            
        except Exception as e:
            self.logger.error(f"Technology detection failed: {e}")
            result['error'] = str(e)
        
        return result
    
    async def _detect_single_target(self, url: str) -> Dict[str, Any]:
        """
        Detect technologies for a single target URL.
        
        Args:
            url (str): Target URL
        
        Returns:
            Detection results
        """
        detection_result = {
            'url': url,
            'accessible': False,
            'technologies': {},
            'frameworks': [],
            'cms': None,
            'programming_languages': [],
            'web_servers': [],
            'cdn': None,
            'analytics': [],
            'security_headers': {},
            'response_info': {}
        }
        
        try:
            # Make HTTP request to analyze the target
            response = await self.network_utils.make_request(url, timeout=10)
            
            if not response:
                return detection_result
            
            detection_result['accessible'] = True
            detection_result['response_info'] = {
                'status_code': response['status'],
                'headers': response['headers'],
                'content_length': len(response['text']),
                'final_url': response['url']
            }
            
            # Analyze different aspects
            await self._analyze_headers(response['headers'], detection_result)
            await self._analyze_html_content(response['text'], detection_result)
            await self._analyze_cookies(response['headers'], detection_result)
            await self._analyze_security_headers(response['headers'], detection_result)
            
            # Additional requests for deeper analysis
            await self._analyze_common_paths(url, detection_result)
            
        except Exception as e:
            self.logger.debug(f"Detection failed for {url}: {e}")
            detection_result['error'] = str(e)
        
        return detection_result
    
    async def _analyze_headers(self, headers: Dict[str, str], result: Dict[str, Any]):
        """
        Analyze HTTP headers for technology indicators.
        
        Args:
            headers (dict): HTTP headers
            result (dict): Detection result to update
        """
        for header_name, header_value in headers.items():
            header_name_lower = header_name.lower()
            header_value_lower = header_value.lower()
            
            # Check header fingerprints
            if header_name_lower in self.tech_fingerprints['headers']:
                for tech, patterns in self.tech_fingerprints['headers'][header_name_lower].items():
                    for pattern in patterns:
                        if re.search(pattern, header_value, re.IGNORECASE):
                            self._add_technology(result, tech, 'header', f"{header_name}: {header_value}")
            
            # Specific header analysis
            if header_name_lower == 'server':
                result['web_servers'].append(header_value)
            elif header_name_lower == 'x-powered-by':
                result['programming_languages'].append(header_value)
            elif header_name_lower in ['cf-ray', 'cf-cache-status']:
                result['cdn'] = 'Cloudflare'
            elif header_name_lower == 'x-amz-cf-id':
                result['cdn'] = 'Amazon CloudFront'
            elif header_name_lower == 'x-served-by':
                if 'fastly' in header_value_lower:
                    result['cdn'] = 'Fastly'
    
    async def _analyze_html_content(self, html_content: str, result: Dict[str, Any]):
        """
        Analyze HTML content for technology indicators.
        
        Args:
            html_content (str): HTML content
            result (dict): Detection result to update
        """
        # Analyze HTML patterns
        for tech, patterns in self.tech_fingerprints['html_content'].items():
            for pattern in patterns:
                if re.search(pattern, html_content, re.IGNORECASE):
                    self._add_technology(result, tech, 'html_content', pattern)
        
        # Analyze script sources
        script_matches = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html_content, re.IGNORECASE)
        for script_src in script_matches:
            for tech, patterns in self.tech_fingerprints['script_sources'].items():
                for pattern in patterns:
                    if re.search(pattern, script_src, re.IGNORECASE):
                        self._add_technology(result, tech, 'script_source', script_src)
        
        # Analyze meta tags
        meta_matches = re.findall(r'<meta[^>]+content=["\']([^"\']+)["\']', html_content, re.IGNORECASE)
        for meta_content in meta_matches:
            for tech, patterns in self.tech_fingerprints['meta_tags'].items():
                for pattern in patterns:
                    if re.search(pattern, meta_content, re.IGNORECASE):
                        self._add_technology(result, tech, 'meta_tag', meta_content)
        
        # CMS Detection
        if any(pattern in html_content.lower() for pattern in ['wp-content', 'wp-includes', 'wordpress']):
            result['cms'] = 'WordPress'
        elif any(pattern in html_content.lower() for pattern in ['drupal.settings', 'sites/default/files']):
            result['cms'] = 'Drupal'
        elif 'joomla' in html_content.lower():
            result['cms'] = 'Joomla'
        elif 'shopify' in html_content.lower():
            result['cms'] = 'Shopify'
    
    async def _analyze_cookies(self, headers: Dict[str, str], result: Dict[str, Any]):
        """
        Analyze cookies for technology indicators.
        
        Args:
            headers (dict): HTTP headers
            result (dict): Detection result to update
        """
        set_cookie_header = headers.get('set-cookie', '')
        
        for tech, cookie_patterns in self.tech_fingerprints['cookies'].items():
            for cookie_pattern in cookie_patterns:
                if cookie_pattern.lower() in set_cookie_header.lower():
                    self._add_technology(result, tech, 'cookie', cookie_pattern)
    
    async def _analyze_security_headers(self, headers: Dict[str, str], result: Dict[str, Any]):
        """
        Analyze security-related headers.
        
        Args:
            headers (dict): HTTP headers
            result (dict): Detection result to update
        """
        security_headers = [
            'strict-transport-security',
            'content-security-policy',
            'x-frame-options',
            'x-content-type-options',
            'x-xss-protection',
            'referrer-policy',
            'permissions-policy'
        ]
        
        for header in security_headers:
            if header in headers:
                result['security_headers'][header] = headers[header]
    
    async def _analyze_common_paths(self, base_url: str, result: Dict[str, Any]):
        """
        Analyze common paths for additional technology detection.
        
        Args:
            base_url (str): Base URL
            result (dict): Detection result to update
        """
        common_paths = [
            '/robots.txt',
            '/sitemap.xml',
            '/.well-known/security.txt',
            '/admin',
            '/wp-admin',
            '/administrator',
            '/manager',
            '/api',
            '/graphql'
        ]
        
        for path in common_paths:
            try:
                url = urljoin(base_url, path)
                response = await self.network_utils.make_request(url, timeout=5)
                
                if response and response['status'] == 200:
                    content = response['text'].lower()
                    
                    # WordPress detection
                    if path == '/wp-admin' and 'wordpress' in content:
                        result['cms'] = 'WordPress'
                        self._add_technology(result, 'WordPress', 'admin_path', path)
                    
                    # Joomla detection
                    elif path == '/administrator' and 'joomla' in content:
                        result['cms'] = 'Joomla'
                        self._add_technology(result, 'Joomla', 'admin_path', path)
                    
                    # API detection
                    elif path == '/api' and ('api' in content or 'json' in content):
                        self._add_technology(result, 'REST API', 'api_endpoint', path)
                    
                    # GraphQL detection
                    elif path == '/graphql' and 'graphql' in content:
                        self._add_technology(result, 'GraphQL', 'api_endpoint', path)
            
            except Exception:
                pass  # Ignore errors for path checking
    
    def _add_technology(self, result: Dict[str, Any], tech_name: str, detection_method: str, evidence: str):
        """
        Add detected technology to results.
        
        Args:
            result (dict): Detection result
            tech_name (str): Technology name
            detection_method (str): How it was detected
            evidence (str): Evidence of detection
        """
        if tech_name not in result['technologies']:
            result['technologies'][tech_name] = {
                'confidence': 0,
                'detection_methods': [],
                'evidence': []
            }
        
        result['technologies'][tech_name]['detection_methods'].append(detection_method)
        result['technologies'][tech_name]['evidence'].append(evidence)
        result['technologies'][tech_name]['confidence'] += 1
        
        # Categorize technologies
        if tech_name in ['WordPress', 'Drupal', 'Joomla', 'Shopify', 'Magento']:
            if tech_name not in result['frameworks']:
                result['frameworks'].append(tech_name)
        elif tech_name in ['React', 'Angular', 'Vue.js', 'jQuery', 'Bootstrap']:
            if tech_name not in result['frameworks']:
                result['frameworks'].append(tech_name)
        elif tech_name in ['Google Analytics', 'Google Tag Manager']:
            if tech_name not in result['analytics']:
                result['analytics'].append(tech_name)
    
    def _generate_detection_summary(self, detections: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate summary of technology detections.
        
        Args:
            detections (dict): All detection results
        
        Returns:
            Summary statistics
        """
        summary = {
            'total_targets_analyzed': len(detections),
            'technologies_found': {},
            'cms_distribution': {},
            'web_server_distribution': {},
            'programming_languages': {},
            'security_score': 0
        }
        
        for url, detection in detections.items():
            # Count technologies
            for tech_name in detection.get('technologies', {}):
                if tech_name in summary['technologies_found']:
                    summary['technologies_found'][tech_name] += 1
                else:
                    summary['technologies_found'][tech_name] = 1
            
            # CMS distribution
            cms = detection.get('cms')
            if cms:
                if cms in summary['cms_distribution']:
                    summary['cms_distribution'][cms] += 1
                else:
                    summary['cms_distribution'][cms] = 1
            
            # Web server distribution
            web_servers = detection.get('web_servers', [])
            for server in web_servers:
                server_name = server.split('/')[0]  # Remove version
                if server_name in summary['web_server_distribution']:
                    summary['web_server_distribution'][server_name] += 1
                else:
                    summary['web_server_distribution'][server_name] = 1
            
            # Security score calculation
            security_headers = detection.get('security_headers', {})
            security_score = len(security_headers) * 10  # 10 points per security header
            summary['security_score'] += security_score
        
        # Average security score
        if summary['total_targets_analyzed'] > 0:
            summary['security_score'] = summary['security_score'] / summary['total_targets_analyzed']
        
        return summary
    
    def _analyze_security_technologies(self, detections: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze security-related technologies and configurations.
        
        Args:
            detections (dict): Detection results
        
        Returns:
            Security analysis
        """
        analysis = {
            'security_findings': [],
            'missing_security_headers': [],
            'outdated_technologies': [],
            'cdn_usage': [],
            'ssl_analysis': {}
        }
        
        important_security_headers = [
            'strict-transport-security',
            'content-security-policy',
            'x-frame-options',
            'x-content-type-options'
        ]
        
        for url, detection in detections.items():
            # Check for missing security headers
            security_headers = detection.get('security_headers', {})
            for header in important_security_headers:
                if header not in security_headers:
                    analysis['missing_security_headers'].append(f"{url} - Missing {header}")
            
            # Check for CDN usage
            cdn = detection.get('cdn')
            if cdn:
                analysis['cdn_usage'].append(f"{url} - Using {cdn}")
            
            # Check for HTTPS usage
            if url.startswith('https://'):
                analysis['ssl_analysis'][url] = 'HTTPS enabled'
            else:
                analysis['security_findings'].append(f"{url} - Using HTTP (insecure)")
            
            # Check for potentially outdated technologies
            technologies = detection.get('technologies', {})
            for tech_name, tech_info in technologies.items():
                # This is a basic check - in production, you'd want a database of CVEs
                if any('php/4' in evidence.lower() for evidence in tech_info.get('evidence', [])):
                    analysis['outdated_technologies'].append(f"{url} - Outdated PHP version detected")
        
        return analysis
    
    async def detect_specific_technology(self, url: str, technology: str) -> Dict[str, Any]:
        """
        Detect a specific technology on a target.
        
        Args:
            url (str): Target URL
            technology (str): Technology to look for
        
        Returns:
            Detection result for specific technology
        """
        self.logger.info(f"Detecting {technology} on {url}")
        
        detection_result = await self._detect_single_target(url)
        
        if technology in detection_result.get('technologies', {}):
            return {
                'url': url,
                'technology': technology,
                'detected': True,
                'details': detection_result['technologies'][technology]
            }
        else:
            return {
                'url': url,
                'technology': technology,
                'detected': False
            }
    
    async def analyze_web_application(self, url: str) -> Dict[str, Any]:
        """
        Perform comprehensive web application analysis.
        
        Args:
            url (str): Target URL
        
        Returns:
            Comprehensive analysis result
        """
        self.logger.info(f"Performing comprehensive web application analysis for {url}")
        
        result = await self._detect_single_target(url)
        
        # Additional analysis
        if result.get('accessible'):
            # Check for common vulnerabilities
            result['vulnerability_indicators'] = await self._check_vulnerability_indicators(url)
            
            # Analyze authentication mechanisms
            result['authentication_analysis'] = await self._analyze_authentication(url)
            
            # Check for admin interfaces
            result['admin_interfaces'] = await self._check_admin_interfaces(url)
        
        return result
    
    async def _check_vulnerability_indicators(self, url: str) -> List[str]:
        """
        Check for common vulnerability indicators.
        
        Args:
            url (str): Target URL
        
        Returns:
            List of vulnerability indicators
        """
        indicators = []
        
        # Check for common vulnerable paths
        vulnerable_paths = [
            '/phpmyadmin',
            '/phpinfo.php',
            '/test.php',
            '/config.php',
            '/backup',
            '/.git',
            '/.svn',
            '/debug'
        ]
        
        for path in vulnerable_paths:
            try:
                test_url = urljoin(url, path)
                response = await self.network_utils.make_request(test_url, timeout=5)
                
                if response and response['status'] == 200:
                    indicators.append(f"Accessible path: {path}")
            except Exception:
                pass
        
        return indicators
    
    async def _analyze_authentication(self, url: str) -> Dict[str, Any]:
        """
        Analyze authentication mechanisms.
        
        Args:
            url (str): Target URL
        
        Returns:
            Authentication analysis
        """
        auth_analysis = {
            'login_pages': [],
            'authentication_methods': [],
            'session_management': []
        }
        
        # Check for common login paths
        login_paths = ['/login', '/signin', '/auth', '/user/login', '/admin/login']
        
        for path in login_paths:
            try:
                test_url = urljoin(url, path)
                response = await self.network_utils.make_request(test_url, timeout=5)
                
                if response and response['status'] == 200:
                    content = response['text'].lower()
                    if any(keyword in content for keyword in ['password', 'username', 'login', 'signin']):
                        auth_analysis['login_pages'].append(path)
            except Exception:
                pass
        
        return auth_analysis
    
    async def _check_admin_interfaces(self, url: str) -> List[str]:
        """
        Check for administrative interfaces.
        
        Args:
            url (str): Target URL
        
        Returns:
            List of discovered admin interfaces
        """
        admin_interfaces = []
        
        admin_paths = [
            '/admin',
            '/administrator',
            '/wp-admin',
            '/manager',
            '/control',
            '/panel'
        ]
        
        for path in admin_paths:
            try:
                test_url = urljoin(url, path)
                response = await self.network_utils.make_request(test_url, timeout=5)
                
                if response and response['status'] in [200, 401, 403]:
                    admin_interfaces.append(path)
            except Exception:
                pass
        
        return admin_interfaces