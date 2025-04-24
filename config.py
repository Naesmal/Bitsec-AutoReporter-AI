import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# OpenAI API Configuration
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
OPENAI_MODEL = os.getenv('OPENAI_MODEL', 'gpt-3.5-turbo')

# Directory Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, 'templates')
OUTPUT_DIR = os.getenv('OUTPUT_DIR', os.path.join(BASE_DIR, 'reports'))

# Ensure output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Debug Mode
DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'

# Confidence Thresholds for Vulnerability Classification
CONFIDENCE_THRESHOLDS = {
    "critical": 0.9,  # If 90% or more miners detect the vulnerability
    "high": 0.7,      # If between 70% and 90% of miners detect the vulnerability
    "medium": 0.5,    # If between 50% and 70% of miners detect the vulnerability
    "low": 0.2        # If between 20% and 50% of miners detect the vulnerability
}

# Vulnerability Categories for Smart Contracts
VULNERABILITY_CATEGORIES = [
    "Reentrancy",
    "Integer Overflow/Underflow",
    "Unauthorized Access",
    "Front-Running",
    "Timestamp Dependence",
    "Gas Limitations",
    "Unchecked External Calls",
    "Logic Errors",
    "Oracle Manipulation",
    "Flash Loan Attacks",
    "Denial of Service",
    "Access Control",
    "Function Visibility",
    "Delegatecall Issues",
    "Transaction Ordering Dependence"
]

# OpenAI Prompt Templates
SUMMARY_PROMPT_TEMPLATE = """
Analyze the following vulnerability findings from multiple security scanners for a smart contract.
The findings have been grouped by vulnerability type and have been detected by {miner_count} different miners.

Vulnerability details:
{vulnerability_details}

Please generate a concise summary of this vulnerability that includes:
1. A clear explanation of the vulnerability in plain language
2. The potential impact if exploited
3. A prioritized recommendation for fixing the issue

Your response should be in markdown format and no longer than 3-4 paragraphs.
"""

REPORT_SUMMARY_PROMPT_TEMPLATE = """
I have analyzed a smart contract and found the following vulnerability categories:
{vulnerability_list}

Overall statistics:
- Total vulnerabilities found: {total_vulnerabilities}
- Critical vulnerabilities: {critical_count}
- High severity vulnerabilities: {high_count}
- Medium severity vulnerabilities: {medium_count}
- Low severity vulnerabilities: {low_count}
- Number of miners that analyzed the contract: {miner_count}

Based on the above information, please generate:
1. An executive summary of the security posture of this contract (2-3 paragraphs)
2. A risk assessment score on a scale of 1-10 (where 10 is extremely risky)
3. A prioritized list of 3-5 key actions to improve the contract's security

Your response should be in markdown format.
"""