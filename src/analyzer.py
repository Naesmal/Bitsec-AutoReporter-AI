from collections import defaultdict
import config

class VulnerabilityAnalyzer:
    """
    Analyzes aggregated vulnerability data to determine severity, risk scores,
    and generate insights.
    """
    
    def __init__(self, aggregated_data):
        """
        Initialize the analyzer with aggregated vulnerability data.
        
        Args:
            aggregated_data (dict): Data aggregated from multiple miners
        """
        self.data = aggregated_data
        self.vulnerabilities = aggregated_data.get('vulnerabilities', [])
        self.total_miners = aggregated_data.get('total_miners', 0)
        self.analyzed_vulns = []
        self.risk_score = 0
    
    def determine_severity_level(self, vulnerability):
        """
        Determine the final severity level based on consensus and reported severity.
        
        Args:
            vulnerability (dict): Aggregated vulnerability data
            
        Returns:
            str: Calculated severity level (critical, high, medium, low, info)
        """
        consensus = vulnerability.get('consensus', 0)
        reported_severity = vulnerability.get('severity', 'unknown').lower()
        
        # Map reported severity to numerical value
        severity_map = {
            'critical': 4,
            'high': 3,
            'medium': 2,
            'low': 1,
            'info': 0,
            'unknown': 1  # Default if unknown
        }
        
        severity_value = severity_map.get(reported_severity, 1)
        
        # Adjust severity based on consensus
        if consensus >= config.CONFIDENCE_THRESHOLDS['critical']:
            # If high consensus, maintain or increase severity
            if severity_value < 3:  # If reported as medium or lower
                severity_value += 1  # Increase by one level
        elif consensus < config.CONFIDENCE_THRESHOLDS['low']:
            # If low consensus, decrease severity
            severity_value = max(0, severity_value - 1)
        
        # Map numerical value back to severity string
        reverse_map = {
            4: 'critical',
            3: 'high',
            2: 'medium',
            1: 'low',
            0: 'info'
        }
        
        return reverse_map.get(severity_value, 'low')
    
    def calculate_risk_score(self):
        """
        Calculate overall risk score for the contract based on vulnerabilities.
        
        Returns:
            float: Risk score from 0 (safe) to 10 (extremely risky)
        """
        if not self.vulnerabilities:
            return 0
        
        # Weights for different severity levels
        severity_weights = {
            'critical': 10,
            'high': 7,
            'medium': 4,
            'low': 1,
            'info': 0
        }
        
        # Calculate weighted score
        total_weight = 0
        total_vulnerabilities = len(self.vulnerabilities)
        
        for vuln in self.analyzed_vulns:
            severity = vuln.get('calculated_severity', 'low')
            consensus = vuln.get('consensus', 0)
            
            # Weight by severity and consensus
            weight = severity_weights.get(severity, 1) * (0.5 + 0.5 * consensus)
            total_weight += weight
        
        # Normalize to 0-10 scale with diminishing returns for many vulnerabilities
        if total_vulnerabilities <= 3:
            # Linear scaling for few vulnerabilities
            risk_score = (total_weight / (3 * severity_weights['critical'])) * 10
        else:
            # Logarithmic scaling for many vulnerabilities to prevent exceeding 10
            import math
            risk_score = (1 - math.exp(-total_weight / 20)) * 10
        
        # Ensure score is between 0 and 10
        risk_score = max(0, min(10, risk_score))
        
        # Round to 1 decimal place
        self.risk_score = round(risk_score, 1)
        return self.risk_score
    
    def analyze(self):
        """
        Analyze all vulnerabilities and enhance data with analysis results.
        
        Returns:
            dict: Enhanced vulnerability data with analysis results
        """
        # Reset analyzed vulnerabilities
        self.analyzed_vulns = []
        
        for vuln in self.vulnerabilities:
            # Determine final severity level
            calculated_severity = self.determine_severity_level(vuln)
            
            # Create enhanced vulnerability object
            enhanced_vuln = vuln.copy()
            enhanced_vuln['calculated_severity'] = calculated_severity
            
            # Calculate confidence level text
            consensus = vuln.get('consensus', 0)
            if consensus >= 0.8:
                confidence = "Very High"
            elif consensus >= 0.6:
                confidence = "High"
            elif consensus >= 0.4:
                confidence = "Medium"
            elif consensus >= 0.2:
                confidence = "Low"
            else:
                confidence = "Very Low"
                
            enhanced_vuln['confidence_level'] = confidence
            enhanced_vuln['confidence_percent'] = f"{int(consensus * 100)}%"
            
            # Add affected lines count
            enhanced_vuln['affected_lines_count'] = len(vuln.get('line_numbers', []))
            
            self.analyzed_vulns.append(enhanced_vuln)
        
        # Calculate risk score
        risk_score = self.calculate_risk_score()
        
        # Group vulnerabilities by severity for easier reporting
        severity_groups = defaultdict(list)
        for vuln in self.analyzed_vulns:
            severity = vuln.get('calculated_severity', 'low')
            severity_groups[severity].append(vuln)
        
        # Count vulnerabilities by severity
        severity_counts = {
            'critical': len(severity_groups.get('critical', [])),
            'high': len(severity_groups.get('high', [])),
            'medium': len(severity_groups.get('medium', [])),
            'low': len(severity_groups.get('low', [])),
            'info': len(severity_groups.get('info', []))
        }
        
        # Prepare result
        result = {
            'contract_hash': self.data.get('contract_hash'),
            'contract_name': self.data.get('contract_name'),
            'total_miners': self.total_miners,
            'vulnerabilities': self.analyzed_vulns,
            'vulnerability_count': len(self.analyzed_vulns),
            'severity_counts': severity_counts,
            'risk_score': risk_score,
            'severity_groups': dict(severity_groups)
        }
        
        return result