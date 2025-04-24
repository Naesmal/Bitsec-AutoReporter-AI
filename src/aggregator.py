import json
import os
import glob
from collections import defaultdict
import re

class ResponseAggregator:
    """
    Aggregates vulnerability responses from multiple miners for the same contract.
    """
    
    def __init__(self, input_dir='sample_data'):
        """
        Initialize the aggregator with the directory containing miner responses.
        
        Args:
            input_dir (str): Path to directory containing miner JSON files
        """
        self.input_dir = input_dir
        self.miner_responses = []
        self.aggregated_data = {}
        self.contract_hash = None
        self.contract_name = None
        
    def load_miner_responses(self, pattern='miner_response_*.json'):
        """
        Load all miner responses from the input directory.
        
        Args:
            pattern (str): Pattern to filter JSON files
            
        Returns:
            int: Number of miner responses loaded
        """
        file_pattern = os.path.join(self.input_dir, pattern)
        json_files = glob.glob(file_pattern)
        
        for file_path in json_files:
            try:
                with open(file_path, 'r') as file:
                    response = json.load(file)
                    self.miner_responses.append(response)
                    
                    # Set contract hash if not set yet
                    if not self.contract_hash and 'contract_hash' in response:
                        self.contract_hash = response['contract_hash']
                    
                    # Set contract name if available
                    if not self.contract_name and 'contract_name' in response:
                        self.contract_name = response['contract_name']
                        
                    if self.contract_hash and self.contract_hash != response.get('contract_hash'):
                        print(f"Warning: Different contract hash in file {file_path}")
                        
                    print(f"Loaded response from miner: {response.get('miner_id', 'unknown')}")
            except Exception as e:
                print(f"Error loading file {file_path}: {e}")
        
        return len(self.miner_responses)
    
    def normalize_vulnerability_type(self, vuln_type):
        """
        Normalize vulnerability types to group similar mentions.
        
        Args:
            vuln_type (str): Raw vulnerability type
            
        Returns:
            str: Normalized vulnerability type
        """
        # Normalization mapping - extend as needed
        normalization_map = {
            "reentrancy": "Reentrancy",
            "reentrancy attack": "Reentrancy",
            "re-entrancy": "Reentrancy",
            "integer overflow": "Integer Overflow/Underflow",
            "integer underflow": "Integer Overflow/Underflow",
            "overflow": "Integer Overflow/Underflow",
            "underflow": "Integer Overflow/Underflow",
            "access control": "Unauthorized Access",
            "unauthorized access": "Unauthorized Access",
            "permission": "Unauthorized Access",
            "timestamp dependence": "Timestamp Dependence",
            "block timestamp": "Timestamp Dependence",
            "frontrunning": "Front-Running",
            "front running": "Front-Running",
            "front-running": "Front-Running",
            "unchecked call": "Unchecked External Calls",
            "unchecked external call": "Unchecked External Calls",
            "external call": "Unchecked External Calls",
            "logic error": "Logic Errors",
            "business logic": "Logic Errors",
            "oracle manipulation": "Oracle Manipulation",
            "price manipulation": "Oracle Manipulation",
            "flash loan": "Flash Loan Attacks",
            "flashloan": "Flash Loan Attacks"
        }
        
        # Convert to lowercase for comparison
        lower_type = vuln_type.lower()
        
        # Find matches in the mapping
        for key, value in normalization_map.items():
            if key in lower_type:
                return value
        
        # If no match is found, return the original type
        return vuln_type
    
    def extract_line_numbers(self, vuln):
        """
        Extract line numbers from vulnerability data, handling various formats.
        
        Args:
            vuln (dict): Vulnerability data
            
        Returns:
            list: Normalized list of line numbers
        """
        line_nums = vuln.get('line_numbers', [])
        
        # If it's already a list, return it
        if isinstance(line_nums, list):
            return line_nums
            
        # If it's a string, try to parse it
        if isinstance(line_nums, str):
            # Try to extract numbers using regex
            numbers = re.findall(r'\d+', line_nums)
            return [int(num) for num in numbers]
            
        # If it's a single number
        if isinstance(line_nums, (int, float)):
            return [int(line_nums)]
            
        return []
    
    def aggregate_vulnerabilities(self):
        """
        Aggregate vulnerabilities reported by all miners.
        
        Returns:
            dict: Aggregated data by vulnerability category
        """
        if not self.miner_responses:
            print("No miner responses loaded. Call load_miner_responses() first.")
            return {}
        
        total_miners = len(self.miner_responses)
        vulnerability_groups = defaultdict(list)
        
        # First pass: group vulnerabilities by normalized type
        for response in self.miner_responses:
            miner_id = response.get('miner_id', 'unknown')
            
            for vuln in response.get('vulnerabilities', []):
                # Normalize the vulnerability type
                norm_type = self.normalize_vulnerability_type(vuln.get('type', 'Unknown'))
                
                # Extract and normalize line numbers
                line_numbers = self.extract_line_numbers(vuln)
                
                vulnerability_groups[norm_type].append({
                    'miner_id': miner_id,
                    'severity': vuln.get('severity', 'unknown'),
                    'line_numbers': line_numbers,
                    'description': vuln.get('description', ''),
                    'code_snippet': vuln.get('code_snippet', ''),
                    'recommendation': vuln.get('recommendation', '')
                })
        
        # Second pass: calculate consensus and organize data
        aggregated_vulnerabilities = []
        
        for vuln_type, instances in vulnerability_groups.items():
            # Calculate consensus percentage
            consensus = len(instances) / total_miners
            
            # Determine severity based on frequency and reported severities
            severity_counts = defaultdict(int)
            for instance in instances:
                severity = instance.get('severity', 'unknown').lower()
                severity_counts[severity] += 1
            
            # Find most commonly reported severity
            max_severity = max(severity_counts.items(), key=lambda x: x[1])[0] if severity_counts else 'unknown'
            
            # Collect all unique line numbers
            all_line_numbers = set()
            for instance in instances:
                all_line_numbers.update(instance.get('line_numbers', []))
            
            # Find the most detailed description and recommendation
            descriptions = [i.get('description', '') for i in instances if i.get('description')]
            recommendations = [i.get('recommendation', '') for i in instances if i.get('recommendation')]
            code_snippets = [i.get('code_snippet', '') for i in instances if i.get('code_snippet')]
            
            # Sort by length to find the most detailed
            best_description = max(descriptions, key=len) if descriptions else ''
            best_recommendation = max(recommendations, key=len) if recommendations else ''
            best_code_snippet = max(code_snippets, key=len) if code_snippets else ''
            
            # Create aggregated vulnerability entry
            aggregated_vuln = {
                'type': vuln_type,
                'consensus': consensus,
                'severity': max_severity,
                'line_numbers': sorted(list(all_line_numbers)),
                'description': best_description,
                'code_snippet': best_code_snippet,
                'recommendation': best_recommendation,
                'miner_count': len(instances),
                'total_miners': total_miners,
                'miner_details': instances  # Keep all individual miner reports for reference
            }
            
            aggregated_vulnerabilities.append(aggregated_vuln)
        
        # Sort by consensus (highest first)
        aggregated_vulnerabilities.sort(key=lambda x: x['consensus'], reverse=True)
        
        # Create the final aggregated data structure
        self.aggregated_data = {
            'contract_hash': self.contract_hash,
            'contract_name': self.contract_name,
            'total_miners': total_miners,
            'vulnerabilities': aggregated_vulnerabilities
        }
        
        return self.aggregated_data
    
    def get_stats(self):
        """
        Calculate statistics about the aggregated vulnerabilities.
        
        Returns:
            dict: Statistics about the vulnerabilities
        """
        if not self.aggregated_data:
            return {}
        
        vulns = self.aggregated_data.get('vulnerabilities', [])
        
        # Count vulnerabilities by severity
        severity_counts = defaultdict(int)
        for vuln in vulns:
            severity = vuln.get('severity', 'unknown').lower()
            severity_counts[severity] += 1
        
        # Calculate consensus distribution
        consensus_levels = {
            'high_consensus': len([v for v in vulns if v.get('consensus', 0) >= 0.7]),
            'medium_consensus': len([v for v in vulns if 0.4 <= v.get('consensus', 0) < 0.7]),
            'low_consensus': len([v for v in vulns if v.get('consensus', 0) < 0.4])
        }
        
        return {
            'total_vulnerabilities': len(vulns),
            'severity_counts': dict(severity_counts),
            'consensus_levels': consensus_levels,
            'unique_vulnerability_types': len(set(v.get('type') for v in vulns))
        }
    
    def save_aggregated_data(self, output_path):
        """
        Save the aggregated data to a JSON file.
        
        Args:
            output_path (str): Path to save the JSON file
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.aggregated_data:
            print("No aggregated data available. Call aggregate_vulnerabilities() first.")
            return False
            
        try:
            with open(output_path, 'w') as f:
                json.dump(self.aggregated_data, f, indent=2)
            print(f"Aggregated data saved to {output_path}")
            return True
        except Exception as e:
            print(f"Error saving aggregated data: {e}")
            return False