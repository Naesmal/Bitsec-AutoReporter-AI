import json
import openai
import time
import config

class OpenAIHandler:
    """
    Handles interactions with the OpenAI API for enhancing vulnerability descriptions,
    recommendations, and generating report summaries.
    """
    
    def __init__(self, api_key=None):
        """
        Initialize the OpenAI handler.
        
        Args:
            api_key (str, optional): OpenAI API key. Defaults to config value.
        """
        self.api_key = api_key or config.OPENAI_API_KEY
        self.model = config.OPENAI_MODEL
        
        if not self.api_key:
            raise ValueError("OpenAI API key is required. Set it in .env file or pass directly.")
            
        openai.api_key = self.api_key
    
    def enhance_vulnerability_description(self, vulnerability):
        """
        Enhance vulnerability description and recommendations using OpenAI.
        
        Args:
            vulnerability (dict): Vulnerability data
            
        Returns:
            dict: Enhanced vulnerability data with improved description and recommendations
        """
        vuln_type = vulnerability.get('type', 'Unknown')
        description = vulnerability.get('description', '')
        code_snippet = vulnerability.get('code_snippet', '')
        recommendation = vulnerability.get('recommendation', '')
        miner_count = vulnerability.get('miner_count', 0)
        total_miners = vulnerability.get('total_miners', 0)
        confidence = f"{int(vulnerability.get('consensus', 0) * 100)}%"
        
        # Prepare detailed information for the prompt
        vulnerability_details = f"""
Type: {vuln_type}
Detected by: {miner_count} out of {total_miners} miners ({confidence} consensus)
Original description: {description}
Code snippet: ```
{code_snippet}
```
Original recommendation: {recommendation}
"""

        # Create prompt using template
        prompt = config.SUMMARY_PROMPT_TEMPLATE.format(
            miner_count=miner_count,
            vulnerability_details=vulnerability_details
        )
        
        try:
            # Call OpenAI API
            response = openai.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a smart contract security expert. Provide clear, accurate, and concise information about vulnerabilities."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=500,
                temperature=0.5
            )
            
            # Extract the enhanced content
            enhanced_content = response.choices[0].message.content.strip()
            
            # Update vulnerability with enhanced content
            enhanced_vuln = vulnerability.copy()
            enhanced_vuln['enhanced_description'] = enhanced_content
            
            return enhanced_vuln
            
        except Exception as e:
            print(f"Error calling OpenAI API: {e}")
            # Return original vulnerability if API call fails
            return vulnerability
    
    def generate_report_summary(self, analysis_result):
        """
        Generate an executive summary for the entire report.
        
        Args:
            analysis_result (dict): Complete analysis result
            
        Returns:
            str: Executive summary in markdown format
        """
        # Extract necessary information
        severity_counts = analysis_result.get('severity_counts', {})
        risk_score = analysis_result.get('risk_score', 0)
        vulnerabilities = analysis_result.get('vulnerabilities', [])
        total_miners = analysis_result.get('total_miners', 0)
        
        # Create a list of vulnerability types
        vuln_list = [f"- {v.get('type')}: {v.get('calculated_severity')} severity, {v.get('confidence_percent')} confidence" 
                    for v in vulnerabilities[:5]]  # Limit to top 5 for the prompt
        
        if len(vulnerabilities) > 5:
            vuln_list.append(f"- Plus {len(vulnerabilities) - 5} more vulnerabilities")
            
        vulnerability_list = "\n".join(vuln_list)
        
        # Create prompt using template
        prompt = config.REPORT_SUMMARY_PROMPT_TEMPLATE.format(
            vulnerability_list=vulnerability_list,
            total_vulnerabilities=len(vulnerabilities),
            critical_count=severity_counts.get('critical', 0),
            high_count=severity_counts.get('high', 0),
            medium_count=severity_counts.get('medium', 0),
            low_count=severity_counts.get('low', 0),
            miner_count=total_miners
        )
        
        try:
            # Call OpenAI API
            response = openai.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a smart contract security expert. Provide clear, concise, and actionable security assessments."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=800,
                temperature=0.7
            )
            
            # Extract the summary
            summary = response.choices[0].message.content.strip()
            return summary
            
        except Exception as e:
            print(f"Error generating report summary: {e}")
            # Return basic summary if API call fails
            return self._generate_fallback_summary(analysis_result)
    
    def _generate_fallback_summary(self, analysis_result):
        """
        Generate a basic summary without using the API.
        
        Args:
            analysis_result (dict): Complete analysis result
            
        Returns:
            str: Basic summary in markdown format
        """
        severity_counts = analysis_result.get('severity_counts', {})
        risk_score = analysis_result.get('risk_score', 0)
        
        summary = f"""
## Executive Summary

This smart contract has been analyzed and found to contain {len(analysis_result.get('vulnerabilities', []))} potential vulnerabilities:
- Critical: {severity_counts.get('critical', 0)}
- High: {severity_counts.get('high', 0)}
- Medium: {severity_counts.get('medium', 0)}
- Low: {severity_counts.get('low', 0)}

The overall risk score for this contract is **{risk_score}/10**.

### Recommended Actions
1. Address critical and high severity issues immediately
2. Review and fix medium severity issues
3. Consider all remaining issues as part of a thorough code review
"""
        return summary