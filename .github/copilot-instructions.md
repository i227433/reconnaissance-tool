# Copilot Instructions

<!-- Use this file to provide workspace-specific custom instructions to Copilot. For more details, visit https://code.visualstudio.com/docs/copilot/copilot-customization#_use-a-githubcopilotinstructionsmd-file -->

This is a Python-based reconnaissance tool for penetration testing and cybersecurity analysis. The project follows a modular architecture with the following guidelines:

## Project Structure
- `main.py` - Entry point with CLI interface
- `modules/` - Individual reconnaissance modules
- `utils/` - Shared utilities and helpers
- `reports/` - Report generation and templates
- `config/` - Configuration files
- `logs/` - Application logs

## Code Style Guidelines
- Follow PEP 8 standards
- Use type hints for all functions
- Implement comprehensive error handling
- Add detailed docstrings for all functions and classes
- Use logging for all operations
- Implement rate limiting for API calls
- Follow security best practices

## Module Requirements
- Each module must be independently callable
- Implement proper logging and error handling
- Support both synchronous and asynchronous operations where beneficial
- Include comprehensive documentation
- Follow the principle of least privilege for network operations
