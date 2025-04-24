# Bitsec AutoReporter AI

## Overview

Bitsec AutoReporter AI is an intelligent report generation tool designed for the Bitsec subnet ecosystem. This tool aggregates vulnerability findings from multiple miners, analyzes consensus patterns, and generates comprehensive, easy-to-understand security reports for smart contracts and code repositories.

## Key Features

- **Intelligent Aggregation**: Clusters similar vulnerabilities reported by different miners
- **Consensus-Based Severity**: Determines vulnerability severity based on miner consensus
- **Natural Language Processing**: Uses OpenAI GPT models to enhance vulnerability descriptions and recommendations
- **Standardized Reporting**: Generates consistent, professional reports in multiple formats (Markdown, HTML)
- **Visualization**: Includes visual representations of findings for better comprehension

## Why This Matters

The Bitsec subnet enables decentralized vulnerability detection through multiple miners analyzing the same code. However, this distributed approach creates a challenge in aggregating and presenting results coherently. AutoReporter AI solves this problem by:

1. Filtering out noise and false positives
2. Organizing findings by severity and type
3. Presenting a unified report that simplifies decision-making
4. Providing actionable recommendations based on consensus

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/bitsec-auto-reporter.git
cd bitsec-auto-reporter

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Edit .env file and add your OpenAI API key
```

## Usage

```bash
# Run with sample data
python main.py --input sample_data --output reports

# Run with custom data directory
python main.py --input /path/to/miner/responses --output /path/to/output
```

## Input Format

The tool expects miner responses in JSON format with the following structure:

```json
{
  "miner_id": "unique-miner-identifier",
  "timestamp": "ISO-8601-timestamp",
  "contract_hash": "analyzed-contract-hash",
  "vulnerabilities": [
    {
      "type": "Vulnerability-Type",
      "severity": "high|medium|low",
      "line_numbers": [45, 46, 47],
      "description": "Description of the vulnerability",
      "code_snippet": "Relevant code",
      "recommendation": "How to fix it"
    }
  ],
  "analysis_summary": "Overall analysis summary"
}
```

## Output

The tool generates reports in multiple formats:
- Markdown: For easy integration with GitHub
- HTML: For web presentation
- JSON: For programmatic processing

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Bitsec subnet community
- Bittensor network