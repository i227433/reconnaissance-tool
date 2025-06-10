"""
Subdomain Enumeration Module
Discovers subdomains using multiple techniques including APIs and wordlist attacks.
"""

import asyncio
import aiohttp
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Set, Optional
from utils.logger import log_performance
from utils.network import NetworkUtils, RateLimiter
from modules.dns_module import DNSModule


class SubdomainModule:
    """Subdomain enumeration functionality for reconnaissance."""
    
    def __init__(self, config):
        """
        Initialize subdomain enumeration module.
        
        Args:
            config: Configuration object
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.network_utils = NetworkUtils(config)
        self.dns_module = DNSModule(config)
        self.rate_limiter = RateLimiter(calls_per_second=2.0)  # Conservative rate limiting
        
        # Load wordlist
        self.wordlist = self._load_wordlist()
    
    @log_performance
    async def enumerate(self, domain: str) -> Dict[str, Any]:
        """
        Perform comprehensive subdomain enumeration.
        
        Args:
            domain (str): Domain to enumerate subdomains for
        
        Returns:
            Dict containing subdomain enumeration results
        """
        self.logger.info(f"Starting subdomain enumeration for {domain}")
        
        result = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'subdomains': set(),
            'active_subdomains': [],
            'subdomain_ips': {},
            'sources': {
                'crt_sh': [],
                'otx': [],
                'wordlist': [],
                'dns_bruteforce': []
            },
            'statistics': {}
        }
        
        try:
            # Run enumeration methods concurrently
            tasks = []
            
            if self.config.get('subdomain_enumeration.use_crt_sh', True):
                tasks.append(self._enumerate_crt_sh(domain))
            
            if self.config.get('subdomain_enumeration.use_otx', True):
                tasks.append(self._enumerate_otx(domain))
            
            if self.wordlist:
                tasks.append(self._enumerate_wordlist(domain))
            
            # Execute all enumeration methods
            enumeration_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for i, enum_result in enumerate(enumeration_results):
                if isinstance(enum_result, Exception):
                    self.logger.error(f"Enumeration method {i} failed: {enum_result}")
                    continue
                
                if isinstance(enum_result, dict):
                    for source, subdomains in enum_result.items():
                        if isinstance(subdomains, (list, set)):
                            result['sources'][source].extend(subdomains)
                            result['subdomains'].update(subdomains)
            
            # Convert set to list for JSON serialization
            all_subdomains = list(result['subdomains'])
            result['subdomains'] = all_subdomains
            
            # Verify subdomains are active
            if all_subdomains:
                active_results = await self._verify_subdomains(all_subdomains)
                result['active_subdomains'] = active_results['active']
                result['subdomain_ips'] = active_results['ips']
            
            # Generate statistics
            result['statistics'] = self._generate_statistics(result)
            
            self.logger.info(f"Subdomain enumeration completed for {domain}. Found {len(result['active_subdomains'])} active subdomains")
            
        except Exception as e:
            self.logger.error(f"Subdomain enumeration failed for {domain}: {e}")
            result['error'] = str(e)
        
        return result
    
    async def _enumerate_crt_sh(self, domain: str) -> Dict[str, List[str]]:
        """
        Enumerate subdomains using Certificate Transparency logs via crt.sh.
        
        Args:
            domain (str): Domain to search
        
        Returns:
            Dict with crt.sh results
        """
        self.logger.info(f"Querying Certificate Transparency logs for {domain}")
        subdomains = []
        
        try:
            await self.rate_limiter.wait()
            
            url = self.config.get('apis.crt_sh_url', 'https://crt.sh/?q={domain}&output=json').format(domain=domain)
            response = await self.network_utils.make_request(url)
            
            if response and response['status'] == 200:
                try:
                    certificates = json.loads(response['text'])
                    
                    for cert in certificates:
                        name_value = cert.get('name_value', '')
                        
                        # Split by newlines as crt.sh can return multiple domains
                        for subdomain in name_value.split('\n'):
                            subdomain = subdomain.strip().lower()
                            
                            # Clean up wildcard certificates
                            if subdomain.startswith('*.'):
                                subdomain = subdomain[2:]
                            
                            # Validate subdomain
                            if (subdomain and 
                                subdomain.endswith(f'.{domain}') and 
                                self.network_utils.is_valid_domain(subdomain)):
                                subdomains.append(subdomain)
                    
                    # Remove duplicates
                    subdomains = list(set(subdomains))
                    self.logger.info(f"Found {len(subdomains)} subdomains from Certificate Transparency")
                    
                except json.JSONDecodeError as e:
                    self.logger.error(f"Failed to parse crt.sh response: {e}")
            
            else:
                self.logger.warning(f"crt.sh query failed with status: {response['status'] if response else 'No response'}")
        
        except Exception as e:
            self.logger.error(f"crt.sh enumeration failed: {e}")
        
        return {'crt_sh': subdomains}
    
    async def _enumerate_otx(self, domain: str) -> Dict[str, List[str]]:
        """
        Enumerate subdomains using AlienVault OTX.
        
        Args:
            domain (str): Domain to search
        
        Returns:
            Dict with OTX results
        """
        self.logger.info(f"Querying AlienVault OTX for {domain}")
        subdomains = []
        
        try:
            await self.rate_limiter.wait()
            
            url = self.config.get('apis.otx_url', 'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns').format(domain=domain)
            response = await self.network_utils.make_request(url)
            
            if response and response['status'] == 200:
                try:
                    data = json.loads(response['text'])
                    passive_dns = data.get('passive_dns', [])
                    
                    for record in passive_dns:
                        hostname = record.get('hostname', '').lower()
                        
                        if (hostname and 
                            hostname.endswith(f'.{domain}') and 
                            self.network_utils.is_valid_domain(hostname)):
                            subdomains.append(hostname)
                    
                    # Remove duplicates
                    subdomains = list(set(subdomains))
                    self.logger.info(f"Found {len(subdomains)} subdomains from OTX")
                    
                except json.JSONDecodeError as e:
                    self.logger.error(f"Failed to parse OTX response: {e}")
            
            else:
                self.logger.warning(f"OTX query failed with status: {response['status'] if response else 'No response'}")
        
        except Exception as e:
            self.logger.error(f"OTX enumeration failed: {e}")
        
        return {'otx': subdomains}
    
    async def _enumerate_wordlist(self, domain: str) -> Dict[str, List[str]]:
        """
        Enumerate subdomains using DNS bruteforce with wordlist.
        
        Args:
            domain (str): Domain to bruteforce
        
        Returns:
            Dict with wordlist results
        """
        self.logger.info(f"Starting DNS bruteforce for {domain}")
        found_subdomains = []
        
        if not self.wordlist:
            self.logger.warning("No wordlist available for bruteforce")
            return {'dns_bruteforce': found_subdomains}
        
        try:
            # Limit wordlist size for performance
            max_words = self.config.get('subdomain_enumeration.max_subdomains', 1000)
            wordlist_subset = self.wordlist[:max_words]
            
            # Create subdomain candidates
            candidates = [f"{word}.{domain}" for word in wordlist_subset]
            
            # DNS resolve in batches
            batch_size = 50
            for i in range(0, len(candidates), batch_size):
                batch = candidates[i:i + batch_size]
                
                # Create DNS check tasks
                tasks = [self.dns_module.check_subdomain_dns(subdomain) for subdomain in batch]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Process results
                for j, result in enumerate(results):
                    if isinstance(result, dict) and result.get('exists'):
                        found_subdomains.append(batch[j])
                
                # Rate limiting between batches
                await asyncio.sleep(0.1)
            
            self.logger.info(f"Found {len(found_subdomains)} subdomains from DNS bruteforce")
            
        except Exception as e:
            self.logger.error(f"Wordlist enumeration failed: {e}")
        
        return {'dns_bruteforce': found_subdomains}
    
    async def _verify_subdomains(self, subdomains: List[str]) -> Dict[str, Any]:
        """
        Verify which subdomains are active and resolve their IPs.
        
        Args:
            subdomains (list): List of subdomains to verify
        
        Returns:
            Dict with active subdomains and their IPs
        """
        self.logger.info(f"Verifying {len(subdomains)} subdomains")
        
        active_subdomains = []
        subdomain_ips = {}
        
        # Batch verification for performance
        batch_size = 20
        for i in range(0, len(subdomains), batch_size):
            batch = subdomains[i:i + batch_size]
            
            # Create verification tasks
            tasks = [self._verify_single_subdomain(subdomain) for subdomain in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for j, result in enumerate(results):
                if isinstance(result, dict) and result.get('active'):
                    subdomain = batch[j]
                    active_subdomains.append(subdomain)
                    if result.get('ips'):
                        subdomain_ips[subdomain] = result['ips']
            
            # Small delay between batches
            await asyncio.sleep(0.1)
        
        self.logger.info(f"Verified {len(active_subdomains)} active subdomains")
        return {'active': active_subdomains, 'ips': subdomain_ips}
    
    async def _verify_single_subdomain(self, subdomain: str) -> Dict[str, Any]:
        """
        Verify if a single subdomain is active.
        
        Args:
            subdomain (str): Subdomain to verify
        
        Returns:
            Dict with verification results
        """
        try:
            # DNS resolution check
            dns_result = await self.dns_module.check_subdomain_dns(subdomain)
            
            if dns_result.get('exists'):
                return {
                    'active': True,
                    'ips': dns_result.get('ip_addresses', []),
                    'cname': dns_result.get('cname')
                }
            
            return {'active': False}
            
        except Exception as e:
            self.logger.debug(f"Verification failed for {subdomain}: {e}")
            return {'active': False}
    
    def _load_wordlist(self) -> List[str]:
        """
        Load subdomain wordlist from file.
        
        Returns:
            List of words for subdomain bruteforce
        """
        wordlist_file = self.config.get('subdomain_enumeration.wordlist_file', 'config/subdomains.txt')
        
        try:
            if Path(wordlist_file).exists():
                with open(wordlist_file, 'r') as f:
                    wordlist = [line.strip().lower() for line in f if line.strip()]
                
                self.logger.info(f"Loaded {len(wordlist)} words from {wordlist_file}")
                return wordlist
            else:
                self.logger.warning(f"Wordlist file not found: {wordlist_file}")
                return []
        
        except Exception as e:
            self.logger.error(f"Failed to load wordlist: {e}")
            return []
    
    def _generate_statistics(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate statistics for subdomain enumeration results.
        
        Args:
            result (dict): Enumeration results
        
        Returns:
            Statistics dictionary
        """
        stats = {
            'total_found': len(result.get('subdomains', [])),
            'total_active': len(result.get('active_subdomains', [])),
            'success_rate': 0.0,
            'sources_summary': {},
            'unique_ips': len(set([ip for ips in result.get('subdomain_ips', {}).values() for ip in ips]))
        }
        
        # Calculate success rate
        if stats['total_found'] > 0:
            stats['success_rate'] = (stats['total_active'] / stats['total_found']) * 100
        
        # Source statistics
        for source, subdomains in result.get('sources', {}).items():
            stats['sources_summary'][source] = len(subdomains)
        
        return stats
    
    async def enumerate_specific_subdomains(self, domain: str, subdomain_list: List[str]) -> Dict[str, Any]:
        """
        Enumerate specific subdomains (useful for targeted reconnaissance).
        
        Args:
            domain (str): Target domain
            subdomain_list (list): Specific subdomains to check
        
        Returns:
            Enumeration results
        """
        self.logger.info(f"Checking specific subdomains for {domain}")
        
        # Construct full subdomain names
        full_subdomains = [f"{sub}.{domain}" for sub in subdomain_list]
        
        # Verify subdomains
        verification_results = await self._verify_subdomains(full_subdomains)
        
        return {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'requested_subdomains': subdomain_list,
            'active_subdomains': verification_results['active'],
            'subdomain_ips': verification_results['ips'],
            'statistics': {
                'requested_count': len(subdomain_list),
                'active_count': len(verification_results['active']),
                'success_rate': (len(verification_results['active']) / len(subdomain_list)) * 100 if subdomain_list else 0
            }
        }
    
    def analyze_subdomain_patterns(self, subdomains: List[str]) -> Dict[str, Any]:
        """
        Analyze patterns in discovered subdomains.
        
        Args:
            subdomains (list): List of discovered subdomains
        
        Returns:
            Pattern analysis
        """
        analysis = {
            'common_prefixes': {},
            'environment_indicators': [],
            'service_indicators': [],
            'interesting_subdomains': []
        }
        
        # Environment indicators
        env_keywords = ['dev', 'test', 'staging', 'prod', 'qa', 'demo', 'beta', 'alpha']
        
        # Service indicators
        service_keywords = ['api', 'admin', 'mail', 'ftp', 'vpn', 'portal', 'dashboard', 'panel']
        
        for subdomain in subdomains:
            # Extract prefix (first part before domain)
            prefix = subdomain.split('.')[0].lower()
            
            # Count prefixes
            if prefix in analysis['common_prefixes']:
                analysis['common_prefixes'][prefix] += 1
            else:
                analysis['common_prefixes'][prefix] = 1
            
            # Check for environment indicators
            if any(env in prefix for env in env_keywords):
                analysis['environment_indicators'].append(subdomain)
            
            # Check for service indicators
            if any(service in prefix for service in service_keywords):
                analysis['service_indicators'].append(subdomain)
            
            # Flag interesting subdomains
            interesting_keywords = ['admin', 'api', 'internal', 'private', 'secret', 'backup', 'old']
            if any(keyword in prefix for keyword in interesting_keywords):
                analysis['interesting_subdomains'].append(subdomain)
        
        # Sort common prefixes by frequency
        analysis['common_prefixes'] = dict(sorted(
            analysis['common_prefixes'].items(), 
            key=lambda x: x[1], 
            reverse=True
        ))
        
        return analysis
