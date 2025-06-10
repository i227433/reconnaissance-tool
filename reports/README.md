# Reports Directory

This directory contains generated reconnaissance reports.

## Report Formats

- **HTML Reports** (`.html`) - Interactive web-based reports with styling
- **Text Reports** (`.txt`) - Plain text reports for terminal viewing  
- **JSON Reports** (`.json`) - Machine-readable reports for automation

## Sample Reports

Sample reports are generated during tool execution and demonstrations.

## Usage

Reports are automatically generated when running the reconnaissance tool:

```bash
python main.py example.com --all --output-format html --output my_report
```

This will create:
- `my_report.html` - Interactive HTML report
- `my_report.txt` - Plain text report
- `my_report.json` - JSON structured data
