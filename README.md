# CyberRecon - Advanced Reconnaissance Tool

<div align="center">

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)

**A comprehensive, modular reconnaissance tool for cybersecurity professionals and penetration testers**

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [Documentation](#documentation) • [Contributing](#contributing)

</div>

## 🚀 Features

### 🔍 Passive Reconnaissance
- **WHOIS Lookup**: Extract comprehensive domain registration information
- **DNS Enumeration**: Query all record types (A, AAAA, MX, NS, TXT, SOA, CNAME)
- **Subdomain Discovery**: Certificate Transparency logs, threat intelligence feeds

### 🎯 Active Reconnaissance
- **Port Scanning**: Socket-based and Nmap integration
- **Banner Grabbing**: Service identification and version detection
- **Technology Detection**: Web framework and server fingerprinting

### 📊 Reporting & Analysis
- **Multiple Formats**: Text, HTML, and JSON reports
- **Comprehensive Analysis**: Executive summaries and technical details
- **Timestamped Results**: Complete audit trail with IP resolution

### ⚡ Advanced Features
- **Modular Architecture**: Independent module execution
- **Parallel Processing**: Optimized performance with async operations
- **Rate Limiting**: Respectful API usage with built-in throttling
- **Error Resilience**: Graceful handling of network issues
- **Docker Support**: Containerized deployment ready

## 📋 Requirements

- Python 3.8+
- nmap (for advanced port scanning)
- Internet connection (for API-based modules)

## 🔧 Installation

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd task1
   ```

2. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Install nmap (optional but recommended):**
   
   **Ubuntu/Debian:**
   ```bash
   sudo apt-get install nmap
   ```
   
   **CentOS/RHEL:**
   ```bash
   sudo yum install nmap
   ```
   
   **Windows:**
   Download from https://nmap.org/download.html
   
   **macOS:**
   ```bash
   brew install nmap
   ```

## 📖 Usage

### Basic Usage

```bash
python main.py --target example.com --all
```

### Individual Modules

```bash
# WHOIS lookup
python main.py --target example.com --whois

# DNS enumeration
python main.py --target example.com --dns

# Subdomain discovery
python main.py --target example.com --subdomains

# Port scanning
python main.py --target example.com --portscan

# Banner grabbing
python main.py --target example.com --banners

# Technology detection
python main.py --target example.com --tech
```

### Advanced Options

```bash
# Custom port range for scanning
python main.py --target example.com --portscan --ports 1-1000

# Specify output format and file
python main.py --target example.com --all --output-format html --output-file report.html

# Adjust verbosity
python main.py --target example.com --dns --verbose

# Quiet mode
python main.py --target example.com --whois --quiet
```

### Configuration

The tool uses a configuration file located at `config/config.yaml`. You can customize:

- **API Keys**: For enhanced subdomain discovery
- **Timeouts**: Network operation timeouts
- **Rate Limits**: API call frequency
- **Default Ports**: Port scanning ranges
- **User Agents**: HTTP request headers

Example configuration:
```yaml
api:
  timeout: 10
  rate_limit: 1.0
  user_agent: "CyberRecon/1.0"

scanning:
  default_ports: "1-1000"
  timeout: 5
  max_threads: 100

subdomain_apis:
  - "https://crt.sh/?q=%25.{domain}&output=json"
  - "https://api.hackertarget.com/hostsearch/?q={domain}"
```

## 🎯 Command Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `--target` | Target domain or IP address | `--target example.com` |
| `--whois` | Perform WHOIS lookup | `--whois` |
| `--dns` | DNS enumeration | `--dns` |
| `--subdomains` | Subdomain discovery | `--subdomains` |
| `--portscan` | Port scanning | `--portscan` |
| `--banners` | Banner grabbing | `--banners` |
| `--tech` | Technology detection | `--tech` |
| `--all` | Run all modules | `--all` |
| `--ports` | Port range for scanning | `--ports 1-1000` |
| `--output-format` | Report format (text/html/json) | `--output-format html` |
| `--output-file` | Output file path | `--output-file report.html` |
| `--verbose` | Increase verbosity | `--verbose` |
| `--quiet` | Quiet mode | `--quiet` |

## 📊 Sample Output

### Text Report
```
=== CyberRecon Report ===
Target: example.com
Scan Date: 2024-01-15 10:30:45

=== WHOIS Information ===
Domain: example.com
Registrar: Example Registrar Inc.
Registration Date: 2023-01-01
Expiration Date: 2025-01-01

=== DNS Records ===
A Records:
- 93.184.216.34

MX Records:
- 10 mail.example.com

=== Open Ports ===
22/tcp  SSH    OpenSSH 8.2
80/tcp  HTTP   nginx/1.18.0
443/tcp HTTPS  nginx/1.18.0

=== Security Analysis ===
• Missing security headers detected
• Outdated software versions found
• Weak SSL/TLS configuration
```

### HTML Report
The HTML report provides a professional, web-based view with:
- Executive summary with risk ratings
- Detailed findings with expandable sections
- Security recommendations
- Interactive charts and graphs
- Professional styling with CSS

## 🏗️ Project Structure

```
task1/
├── main.py                 # CLI entry point
├── config/
│   └── config.yaml        # Configuration file
├── modules/
│   ├── whois_module.py    # WHOIS functionality
│   ├── dns_module.py      # DNS enumeration
│   ├── subdomain_module.py # Subdomain discovery
│   ├── port_scanner.py    # Port scanning
│   ├── banner_grabber.py  # Banner grabbing
│   └── tech_detector.py   # Technology detection
├── utils/
│   ├── logger.py          # Logging utilities
│   ├── config.py          # Configuration management
│   └── network.py         # Network utilities
├── reports/
│   └── report_generator.py # Report generation
├── logs/                  # Application logs
└── requirements.txt       # Python dependencies
```

## 🔒 Security Considerations

### Ethical Usage
- **Authorization Required**: Only scan systems you own or have explicit permission to test
- **Responsible Disclosure**: Report vulnerabilities through proper channels
- **Rate Limiting**: Tool includes built-in rate limiting to avoid overwhelming targets
- **Legal Compliance**: Ensure compliance with local laws and regulations

### Privacy Protection
- **No Data Storage**: Tool doesn't store scan results permanently
- **Anonymization**: Consider using VPN/proxy for sensitive assessments
- **Log Management**: Review and sanitize logs before sharing

## 🐛 Troubleshooting

### Common Issues

**1. Permission Denied Errors**
```bash
# Run with appropriate permissions for port scanning
sudo python main.py --target example.com --portscan
```

**2. DNS Resolution Failures**
```bash
# Check DNS configuration
nslookup example.com
```

**3. Network Timeouts**
```bash
# Increase timeout in config/config.yaml
api:
  timeout: 30
```

**4. Missing Dependencies**
```bash
# Reinstall requirements
pip install -r requirements.txt --force-reinstall
```

### Debug Mode

Enable debug logging for troubleshooting:
```bash
python main.py --target example.com --all --verbose
```

Check logs in the `logs/` directory for detailed information.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Commit changes: `git commit -am 'Add feature'`
4. Push to branch: `git push origin feature-name`
5. Submit a pull request

### Development Guidelines

- Follow PEP 8 coding standards
- Add type hints to all functions
- Include comprehensive docstrings
- Write unit tests for new modules
- Update documentation for new features

## 📜 License

This tool is provided for educational and authorized security testing purposes only. Users are responsible for ensuring compliance with applicable laws and regulations.

## 🙏 Acknowledgments

- **nmap**: Network exploration and security auditing
- **Python asyncio**: Asynchronous programming support
- **Various APIs**: Subdomain enumeration services
- **Security Community**: Vulnerability research and disclosure

## 📞 Support

For questions, issues, or contributions:
- Create an issue in the repository
- Follow the contribution guidelines
- Review existing documentation

---

**⚠️ Disclaimer**: This tool is intended for authorized security testing only. Users are responsible for ensuring they have proper authorization before scanning any systems. Unauthorized scanning may be illegal in your jurisdiction.