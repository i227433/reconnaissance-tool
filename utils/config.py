"""
Configuration management for the reconnaissance tool.
Handles loading and managing configuration from files and command-line arguments.
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, Optional
import logging


class Config:
    """Configuration manager for the reconnaissance tool."""
    
    DEFAULT_CONFIG = {
        "general": {
            "threads": 50,
            "timeout": 5,
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "rate_limit_delay": 1.0,
            "max_retries": 3
        },
        "dns": {
            "nameservers": ["8.8.8.8", "8.8.4.4", "1.1.1.1"],
            "record_types": ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"],
            "timeout": 5
        },
        "port_scanning": {
            "common_ports": [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080],
            "full_port_range": [1, 65535],
            "scan_type": "tcp",
            "timeout": 3,
            "threads": 100
        },
        "subdomain_enumeration": {
            "wordlist_file": "config/subdomains.txt",
            "use_crt_sh": True,
            "use_otx": True,
            "max_subdomains": 1000,
            "verify_subdomains": True
        },
        "banner_grabbing": {
            "timeout": 5,
            "buffer_size": 1024,
            "common_banners": ["SSH", "HTTP", "FTP", "SMTP", "TELNET"]
        },
        "technology_detection": {
            "check_headers": True,
            "check_content": True,
            "follow_redirects": True,
            "max_redirects": 5
        },
        "apis": {
            "crt_sh_url": "https://crt.sh/?q={domain}&output=json",
            "otx_url": "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            "wappalyzer_url": "https://api.wappalyzer.com/lookup/v1/?url={url}",
            "virustotal_url": "https://www.virustotal.com/vtapi/v2/domain/report"
        },
        "output": {
            "reports_dir": "reports",
            "logs_dir": "logs",
            "include_timestamps": True,
            "include_raw_data": False
        }
    }
    
    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize configuration.
        
        Args:
            config_file (str, optional): Path to configuration file
        """
        self.logger = logging.getLogger(__name__)
        self.config = self.DEFAULT_CONFIG.copy()
        
        if config_file and os.path.exists(config_file):
            self.load_from_file(config_file)
        
        # Create default config file if it doesn't exist
        self.ensure_config_file()
        
        # Create default wordlist if it doesn't exist
        self.ensure_wordlist_file()
    
    def load_from_file(self, config_file: str) -> None:
        """
        Load configuration from a JSON file.
        
        Args:
            config_file (str): Path to configuration file
        """
        try:
            with open(config_file, 'r') as f:
                file_config = json.load(f)
              # Deep merge configuration
            self._deep_merge(self.config, file_config)
            self.logger.info(f"Configuration loaded from {config_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to load configuration from {config_file}: {e}")
    
    def save_to_file(self, config_file: str) -> None:
        """
        Save current configuration to a JSON file.
        
        Args:
            config_file (str): Path to save configuration
        """
        try:
            # Ensure directory exists
            Path(config_file).parent.mkdir(parents=True, exist_ok=True)
            
            with open(config_file, 'w') as f:
                json.dump(self.config, f, indent=4)
            
            self.logger.info(f"Configuration saved to {config_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to save configuration to {config_file}: {e}")
    
    def update_from_args(self, args) -> None:
        """
        Update configuration from command-line arguments.
        
        Args:
            args: Parsed command-line arguments
        """
        if hasattr(args, 'threads') and args.threads:
            self.config['general']['threads'] = args.threads
        
        if hasattr(args, 'timeout') and args.timeout:
            self.config['general']['timeout'] = args.timeout
            
        if hasattr(args, 'rate_limit') and args.rate_limit:
            self.config['general']['rate_limit_delay'] = args.rate_limit
            
        if hasattr(args, 'ports') and args.ports:
            self.config['port_scanning']['custom_ports'] = args.ports
            
        if hasattr(args, 'scan_type') and args.scan_type:
            self.config['port_scanning']['scan_type'] = args.scan_type
            
        if hasattr(args, 'subdomain_wordlist') and args.subdomain_wordlist:
            self.config['subdomain_enumeration']['wordlist_file'] = args.subdomain_wordlist
            
        if hasattr(args, 'verbose') and args.verbose:
            self.config['general']['verbose'] = True
            
        if hasattr(args, 'quiet') and args.quiet:
            self.config['general']['quiet'] = True
            
        if hasattr(args, 'json') and args.json:
            self.config['output']['include_json'] = True
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation.
        
        Args:
            key (str): Configuration key (e.g., 'general.threads')
            default: Default value if key not found
        
        Returns:
            Configuration value or default
        """
        keys = key.split('.')
        value = self.config
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key: str, value: Any) -> None:
        """
        Set configuration value using dot notation.
        
        Args:
            key (str): Configuration key (e.g., 'general.threads')
            value: Value to set
        """
        keys = key.split('.')
        config = self.config
        
        # Navigate to the parent dictionary
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        # Set the value
        config[keys[-1]] = value
    
    def _deep_merge(self, target: Dict, source: Dict) -> None:
        """
        Deep merge two dictionaries.
        
        Args:
            target (dict): Target dictionary
            source (dict): Source dictionary to merge
        """
        for key, value in source.items():
            if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                self._deep_merge(target[key], value)
            else:
                target[key] = value
    
    def ensure_config_file(self) -> None:
        """Ensure default configuration file exists."""
        config_file = "config/recon_config.json"
        if not os.path.exists(config_file):
            self.save_to_file(config_file)
    
    def ensure_wordlist_file(self) -> None:
        """Ensure default subdomain wordlist exists."""
        wordlist_file = self.get('subdomain_enumeration.wordlist_file', 'config/subdomains.txt')
        
        if not os.path.exists(wordlist_file):
            # Create default subdomain wordlist
            default_subdomains = [
                "www", "mail", "ftp", "api", "admin", "test", "dev", "staging",
                "blog", "shop", "store", "news", "support", "help", "docs",
                "secure", "portal", "app", "mobile", "m", "wap", "cdn",
                "static", "media", "img", "images", "video", "download",
                "files", "uploads", "assets", "js", "css", "subdomain",
                "sub", "vpn", "remote", "email", "webmail", "mx", "mx1",
                "mx2", "smtp", "pop", "imap", "ns", "ns1", "ns2", "dns",
                "whois", "server", "host", "gateway", "router", "firewall",
                "proxy", "cache", "lb", "balancer", "cluster", "node"
            ]
            
            try:
                Path(wordlist_file).parent.mkdir(parents=True, exist_ok=True)
                with open(wordlist_file, 'w') as f:
                    f.write('\n'.join(default_subdomains))
                self.logger.info(f"Default subdomain wordlist created at {wordlist_file}")
            except Exception as e:
                self.logger.error(f"Failed to create wordlist file: {e}")
    
    def validate(self) -> bool:
        """
        Validate configuration settings.
        
        Returns:
            bool: True if configuration is valid
        """
        try:
            # Validate basic types
            assert isinstance(self.get('general.threads'), int)
            assert isinstance(self.get('general.timeout'), (int, float))
            assert isinstance(self.get('general.user_agent'), str)
            
            # Validate ranges
            assert 1 <= self.get('general.threads') <= 1000
            assert 0.1 <= self.get('general.timeout') <= 300
            
            self.logger.info("Configuration validation passed")
            return True
            
        except (AssertionError, TypeError) as e:
            self.logger.error(f"Configuration validation failed: {e}")
            return False
