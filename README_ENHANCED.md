# CyberRecon - Advanced Reconnaissance Tool

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/docker-supported-blue.svg)](https://www.docker.com/)
[![Security](https://img.shields.io/badge/security-penetration%20testing-red.svg)](https://github.com)

A comprehensive CLI-based reconnaissance tool designed for penetration testing and cybersecurity analysis. CyberRecon provides both passive and active reconnaissance capabilities with professional reporting features.

## 🚀 Features

### 🔍 Passive Reconnaissance
- **WHOIS Lookup**: Domain registration and ownership information
- **DNS Enumeration**: Complete DNS record analysis (A, AAAA, MX, NS, TXT, SOA, CNAME)
- **Subdomain Discovery**: API-based subdomain enumeration with multiple sources
  - Certificate Transparency logs (crt.sh)
  - Threat intelligence feeds (AlienVault OTX)
  - DNS brute-forcing with custom wordlists

### 🎯 Active Reconnaissance
- **Port Scanning**: Fast socket-based and nmap-wrapper scanning
  - TCP/UDP/SYN scan types
  - Custom port ranges
  - Service detection
- **Banner Grabbing**: Protocol-specific service identification
- **Technology Detection**: Web technology fingerprinting and CMS detection

### 📊 Reporting & Analysis
- **Multiple Formats**: Text, HTML, and JSON reports
- **Security Analysis**: Vulnerability indicators and risk assessment
- **Executive Summary**: High-level findings for stakeholders
- **Actionable Recommendations**: Specific security improvements
- **Timestamped Results**: Complete audit trail

### ⚡ Advanced Features
- **Asynchronous Operations**: High-performance concurrent scanning
- **Rate Limiting**: Respectful API usage and target protection
- **Modular Architecture**: Independent module execution
- **Docker Support**: Containerized deployment
- **Comprehensive Logging**: Debug and audit capabilities
- **Configuration Management**: Flexible YAML/JSON configuration

## 📋 Requirements

- **Python 3.8+**
- **nmap** (for advanced port scanning)
- **Internet connection** (for API-based modules)
- **Administrative privileges** (for privileged port scanning)

### System Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install python3 python3-pip nmap dnsutils whois
```

**CentOS/RHEL:**
```bash
sudo yum install python3 python3-pip nmap bind-utils whois
```

**Windows:**
- Install Python 3.8+ from [python.org](https://www.python.org)
- Install nmap from [nmap.org](https://nmap.org/download.html)

**macOS:**
```bash
brew install python3 nmap
```

## 🔧 Installation

### Method 1: Git Clone (Recommended)
```bash
# Clone the repository
git clone https://github.com/your-org/cyberrecon.git
cd cyberrecon

# Install Python dependencies
pip install -r requirements.txt

# Verify installation
python main.py --help
```

### Method 2: Docker Installation
```bash
# Build Docker image
docker build -t cyberrecon .

# Or use Docker Compose
docker-compose build
```

### Method 3: Standalone Installation
```bash
# Download requirements
wget https://raw.githubusercontent.com/your-org/cyberrecon/main/requirements.txt

# Install dependencies
pip install -r requirements.txt

# Download main script
wget https://raw.githubusercontent.com/your-org/cyberrecon/main/main.py
```

## 📖 Usage

### Quick Start
```bash
# Basic reconnaissance scan
python main.py example.com --all

# Generate HTML report
python main.py example.com --all --output-format html --output my_scan
```

### Individual Modules

```bash
# WHOIS lookup
python main.py example.com --whois

# DNS enumeration
python main.py example.com --dns

# Subdomain discovery
python main.py example.com --subdomains

# Port scanning with custom range
python main.py example.com --portscan --ports 1-1000

# Banner grabbing
python main.py example.com --banners

# Technology detection
python main.py example.com --tech
```

### Advanced Usage

```bash
# Comprehensive scan with custom options
python main.py example.com --all \
  --ports 1-65535 \
  --scan-type syn \
  --output-format both \
  --output comprehensive_scan \
  --verbose \
  --threads 100 \
  --timeout 10

# Quiet scan with JSON output
python main.py example.com --dns --portscan --quiet --json

# Custom configuration
python main.py example.com --all --config /path/to/custom_config.json

# Rate-limited scan for sensitive targets
python main.py example.com --all --rate-limit 2.0 --threads 10
```

### Docker Usage

```bash
# Basic Docker scan
docker run --rm -v $(pwd)/reports:/app/reports cyberrecon example.com --all

# Docker with custom config
docker run --rm \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/reports:/app/reports \
  cyberrecon example.com --all --config /app/config/custom.json

# Docker Compose
docker-compose run --rm cyberrecon example.com --all

# Privileged scanning (for advanced port scans)
docker run --rm --privileged \
  -v $(pwd)/reports:/app/reports \
  cyberrecon example.com --portscan --ports 1-65535
```

## 🎯 Command Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `target` | Target domain or IP address | `example.com` |
| `--whois` | Perform WHOIS lookup | `--whois` |
| `--dns` | DNS enumeration | `--dns` |
| `--subdomains` | Subdomain discovery | `--subdomains` |
| `--portscan` | Port scanning | `--portscan` |
| `--banners` | Banner grabbing | `--banners` |
| `--tech` | Technology detection | `--tech` |
| `--all` | Run all modules | `--all` |
| `--ports` | Port range for scanning | `--ports 1-1000` |
| `--scan-type` | Scan type (tcp/syn/udp) | `--scan-type syn` |
| `--output-format` | Report format | `--output-format html` |
| `--output` | Output file name | `--output my_scan` |
| `--json` | Generate JSON output | `--json` |
| `--config` | Configuration file | `--config custom.json` |
| `--threads` | Concurrent threads | `--threads 100` |
| `--timeout` | Network timeout | `--timeout 10` |
| `--rate-limit` | Rate limiting delay | `--rate-limit 1.5` |
| `--verbose` | Verbose output | `--verbose` |
| `--quiet` | Quiet mode | `--quiet` |
| `--log-level` | Logging level | `--log-level DEBUG` |

## 🐳 Docker Deployment

### Building the Image
```bash
# Build with default settings
docker build -t cyberrecon .

# Build with custom tag
docker build -t cyberrecon:v1.0 .
```

### Running Containers
```bash
# Basic container run
docker run --rm cyberrecon example.com --help

# With volume mounts
docker run --rm \
  -v $(pwd)/reports:/app/reports \
  -v $(pwd)/config:/app/config:ro \
  cyberrecon example.com --all

# Interactive mode
docker run --rm -it cyberrecon /bin/bash
```

## 🧪 Testing & Validation

### Comprehensive Demo
```bash
# Run comprehensive demonstration
python comprehensive_demo.py
```

### System Validation
```bash
# Validate all components
python comprehensive_validator.py
```

### Manual Testing
```bash
# Test individual modules
python main.py example.com --whois --verbose
python main.py example.com --dns --log-level DEBUG
```

## 🔒 Security & Legal

### ⚠️ Important Disclaimers
- **Authorization Required**: Only scan systems you own or have explicit permission to test
- **Legal Compliance**: Ensure compliance with local laws and regulations
- **Responsible Use**: Follow ethical hacking guidelines
- **No Warranty**: Tool provided as-is for educational purposes

### Security Features
- Non-privileged Docker containers
- Rate limiting to prevent abuse
- Comprehensive audit logging
- Input validation and sanitization

## 🤝 Contributing

We welcome contributions! Please:
1. Fork the repository
2. Create a feature branch
3. Follow PEP 8 coding standards
4. Add comprehensive tests
5. Update documentation
6. Submit a pull request

## 📜 License

MIT License - See [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **nmap**: Network exploration and security auditing
- **Python asyncio**: Asynchronous programming support
- **Certificate Transparency**: Subdomain enumeration data
- **Security Community**: Vulnerability research and disclosure

---

**⚠️ Disclaimer**: This tool is intended for authorized security testing only. Users must ensure proper permission before scanning systems. Developers are not responsible for misuse.