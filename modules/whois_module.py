"""
WHOIS Lookup Module
Performs comprehensive WHOIS queries to gather domain registration information.
"""

import whois
import asyncio
import logging
from datetime import datetime
from typing import Dict, Any, Optional
from utils.logger import log_performance


class WhoisModule:
    """WHOIS lookup functionality for domain reconnaissance."""
    
    def __init__(self, config):
        """
        Initialize WHOIS module.
        
        Args:
            config: Configuration object
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
    
    @log_performance
    async def lookup(self, domain: str) -> Dict[str, Any]:
        """
        Perform WHOIS lookup for a domain.
        
        Args:
            domain (str): Domain name to lookup
        
        Returns:
            Dict containing WHOIS information
        """
        self.logger.info(f"Starting WHOIS lookup for {domain}")
        
        try:
            # Run WHOIS lookup in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            whois_data = await loop.run_in_executor(None, self._get_whois_data, domain)
            
            if whois_data:
                result = self._parse_whois_data(whois_data)
                result['timestamp'] = datetime.now().isoformat()
                result['domain'] = domain
                
                self.logger.info(f"WHOIS lookup completed for {domain}")
                return result
            else:
                self.logger.warning(f"No WHOIS data found for {domain}")
                return {
                    'domain': domain,
                    'timestamp': datetime.now().isoformat(),
                    'error': 'No WHOIS data available'
                }
                
        except Exception as e:
            self.logger.error(f"WHOIS lookup failed for {domain}: {e}")
            return {
                'domain': domain,
                'timestamp': datetime.now().isoformat(),
                'error': str(e)
            }
    
    def _get_whois_data(self, domain: str) -> Optional[Any]:
        """
        Get raw WHOIS data for a domain.
        
        Args:
            domain (str): Domain name
        
        Returns:
            Raw WHOIS data or None
        """
        try:
            return whois.whois(domain)
        except Exception as e:
            self.logger.error(f"Failed to get WHOIS data for {domain}: {e}")
            return None
    
    def _parse_whois_data(self, whois_data: Any) -> Dict[str, Any]:
        """
        Parse and structure WHOIS data.
        
        Args:
            whois_data: Raw WHOIS data object
        
        Returns:
            Structured WHOIS information
        """
        result = {
            'registrar': None,
            'creation_date': None,
            'expiration_date': None,
            'updated_date': None,
            'name_servers': [],
            'registrant': {},
            'admin_contact': {},
            'tech_contact': {},
            'status': [],
            'dnssec': None,
            'raw_data': None
        }
        
        try:
            # Basic information
            result['registrar'] = self._safe_get_attr(whois_data, 'registrar')
            result['dnssec'] = self._safe_get_attr(whois_data, 'dnssec')
            
            # Dates
            result['creation_date'] = self._format_date(
                self._safe_get_attr(whois_data, 'creation_date')
            )
            result['expiration_date'] = self._format_date(
                self._safe_get_attr(whois_data, 'expiration_date')
            )
            result['updated_date'] = self._format_date(
                self._safe_get_attr(whois_data, 'updated_date')
            )
            
            # Name servers
            name_servers = self._safe_get_attr(whois_data, 'name_servers')
            if name_servers:
                if isinstance(name_servers, list):
                    result['name_servers'] = [ns.lower() for ns in name_servers if ns]
                else:
                    result['name_servers'] = [name_servers.lower()]
            
            # Status
            status = self._safe_get_attr(whois_data, 'status')
            if status:
                if isinstance(status, list):
                    result['status'] = status
                else:
                    result['status'] = [status]
            
            # Contact information
            result['registrant'] = self._extract_contact_info(whois_data, 'registrant')
            result['admin_contact'] = self._extract_contact_info(whois_data, 'admin')
            result['tech_contact'] = self._extract_contact_info(whois_data, 'tech')
            
            # Raw data for reference
            if hasattr(whois_data, 'text'):
                result['raw_data'] = whois_data.text
            
        except Exception as e:
            self.logger.error(f"Error parsing WHOIS data: {e}")
        
        return result
    
    def _safe_get_attr(self, obj: Any, attr: str) -> Any:
        """
        Safely get attribute from object.
        
        Args:
            obj: Object to get attribute from
            attr (str): Attribute name
        
        Returns:
            Attribute value or None
        """
        try:
            value = getattr(obj, attr, None)
            # Handle case where attribute is a list with one element
            if isinstance(value, list) and len(value) == 1:
                return value[0]
            return value
        except Exception:
            return None
    
    def _format_date(self, date_obj: Any) -> Optional[str]:
        """
        Format date object to ISO string.
        
        Args:
            date_obj: Date object
        
        Returns:
            ISO formatted date string or None
        """
        try:
            if date_obj is None:
                return None
            
            if isinstance(date_obj, datetime):
                return date_obj.isoformat()
            elif isinstance(date_obj, list) and date_obj:
                # Take the first date if multiple
                first_date = date_obj[0]
                if isinstance(first_date, datetime):
                    return first_date.isoformat()
            
            # Try to parse as string
            if isinstance(date_obj, str):
                return date_obj
            
            return str(date_obj)
            
        except Exception:
            return None
    
    def _extract_contact_info(self, whois_data: Any, contact_type: str) -> Dict[str, Any]:
        """
        Extract contact information from WHOIS data.
        
        Args:
            whois_data: WHOIS data object
            contact_type (str): Type of contact (registrant, admin, tech)
        
        Returns:
            Contact information dictionary
        """
        contact_info = {}
        
        # Common contact fields
        fields = ['name', 'organization', 'address', 'city', 'state', 'zipcode', 'country', 'email', 'phone', 'fax']
        
        for field in fields:
            # Try different attribute name patterns
            attr_names = [
                f'{contact_type}_{field}',
                f'{field}',
                f'registrant_{field}' if contact_type == 'registrant' else None
            ]
            
            for attr_name in attr_names:
                if attr_name:
                    value = self._safe_get_attr(whois_data, attr_name)
                    if value:
                        contact_info[field] = value
                        break
        
        return contact_info
    
    async def bulk_lookup(self, domains: list) -> Dict[str, Dict[str, Any]]:
        """
        Perform WHOIS lookup for multiple domains.
        
        Args:
            domains (list): List of domain names
        
        Returns:
            Dictionary mapping domains to their WHOIS data
        """
        self.logger.info(f"Starting bulk WHOIS lookup for {len(domains)} domains")
        
        tasks = []
        for domain in domains:
            task = asyncio.create_task(self.lookup(domain))
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        bulk_results = {}
        for i, result in enumerate(results):
            domain = domains[i]
            if isinstance(result, Exception):
                bulk_results[domain] = {
                    'domain': domain,
                    'timestamp': datetime.now().isoformat(),
                    'error': str(result)
                }
            else:
                bulk_results[domain] = result
        
        self.logger.info(f"Bulk WHOIS lookup completed for {len(domains)} domains")
        return bulk_results
    
    def extract_key_info(self, whois_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract key information from WHOIS result for summary.
        
        Args:
            whois_result (dict): WHOIS lookup result
        
        Returns:
            Key information summary
        """
        if 'error' in whois_result:
            return {'status': 'error', 'message': whois_result['error']}
        
        key_info = {
            'status': 'success',
            'registrar': whois_result.get('registrar', 'Unknown'),
            'creation_date': whois_result.get('creation_date'),
            'expiration_date': whois_result.get('expiration_date'),
            'name_servers': whois_result.get('name_servers', []),
            'registrant_org': whois_result.get('registrant', {}).get('organization', 'Unknown'),
            'admin_email': whois_result.get('admin_contact', {}).get('email', 'Unknown')
        }
        
        # Calculate domain age
        if key_info['creation_date']:
            try:
                if isinstance(key_info['creation_date'], str):
                    creation = datetime.fromisoformat(key_info['creation_date'].replace('Z', '+00:00'))
                else:
                    creation = key_info['creation_date']
                
                age_days = (datetime.now() - creation.replace(tzinfo=None)).days
                key_info['domain_age_days'] = age_days
            except Exception:
                key_info['domain_age_days'] = None
        
        return key_info
