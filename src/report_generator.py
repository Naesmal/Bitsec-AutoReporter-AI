import os
import json
import datetime
from jinja2 import Environment, FileSystemLoader
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
from mdutils.mdutils import MdUtils
import config

class ReportGenerator:
    """
    Generates formatted reports from analyzed vulnerability data.
    """
    
    def __init__(self, analysis_result, output_dir=None):
        """
        Initialize the report generator.
        
        Args:
            analysis_result (dict): Complete analysis result
            output_dir (str, optional): Directory to save reports. Defaults to config value.
        """
        self.analysis = analysis_result
        self.output_dir = output_dir or config.OUTPUT_DIR
        
        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Load Jinja2 templates
        self.template_env = Environment(loader=FileSystemLoader(config.TEMPLATES_DIR))
        
        # Prepare base filename
        contract_name = self.analysis.get('contract_name', 'unknown')
        contract_hash = self.analysis.get('contract_hash', 'unknown')
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        self.base_filename = f"{contract_name}_{contract_hash[:8]}_{timestamp}"
    
    def generate_charts(self):
        """
        Generate charts for the report.
        
        Returns:
            dict: Paths to generated chart images
        """
        charts = {}
        
        # Severity distribution pie chart
        severity_counts = self.analysis.get('severity_counts', {})
        
        if sum(severity_counts.values()) > 0:
            # Create severity distribution chart
            plt.figure(figsize=(8, 6))
            
            # Prepare data
            labels = []
            sizes = []
            colors = []
            
            # Define colors and process data
            severity_colors = {
                'critical': '#FF2D00',
                'high': '#FF8C00',
                'medium': '#FFD700',
                'low': '#90EE90',
                'info': '#ADD8E6'
            }
            
            for severity, count in severity_counts.items():
                if count > 0:
                    labels.append(f"{severity.capitalize()} ({count})")
                    sizes.append(count)
                    colors.append(severity_colors.get(severity.lower(), '#CCCCCC'))
            
            # Create pie chart
            plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
            plt.axis('equal')
            plt.title('Vulnerability Severity Distribution')
            
            # Save chart
            severity_chart_path = os.path.join(self.output_dir, f"{self.base_filename}_severity_chart.png")
            plt.savefig(severity_chart_path, bbox_inches='tight')
            plt.close()
            
            charts['severity_chart'] = severity_chart_path
        
        # Create confidence level chart for top vulnerabilities
        vulnerabilities = self.analysis.get('vulnerabilities', [])
        
        if vulnerabilities:
            # Limit to top 5 vulnerabilities
            top_vulns = sorted(vulnerabilities, key=lambda x: x.get('consensus', 0), reverse=True)[:5]
            
            # Prepare data
            vuln_types = [v.get('type', 'Unknown')[:20] + '...' if len(v.get('type', 'Unknown')) > 20 
                         else v.get('type', 'Unknown') for v in top_vulns]
            confidence_values = [v.get('consensus', 0) * 100 for v in top_vulns]
            
            # Create horizontal bar chart
            plt.figure(figsize=(10, 6))
            bars = plt.barh(vuln_types, confidence_values, color='#3498db')
            plt.xlabel('Consensus Percentage (%)')
            plt.title('Top Vulnerabilities by Miner Consensus')
            plt.xlim(0, 100)
            plt.tight_layout()
            
            # Add percentage labels
            for bar in bars:
                width = bar.get_width()
                plt.text(width + 2, bar.get_y() + bar.get_height()/2, 
                        f'{width:.1f}%', ha='left', va='center')
            
            # Save chart
            consensus_chart_path = os.path.join(self.output_dir, f"{self.base_filename}_consensus_chart.png")
            plt.savefig(consensus_chart_path, bbox_inches='tight')
            plt.close()
            
            charts['consensus_chart'] = consensus_chart_path
        
        return charts
    
    def generate_markdown_report(self, executive_summary, charts=None):
        """
        Generate a Markdown report.
        
        Args:
            executive_summary (str): Executive summary text
            charts (dict, optional): Paths to chart images
            
        Returns:
            str: Path to generated report
        """
        # Create markdown file
        report_file = os.path.join(self.output_dir, f"{self.base_filename}_report.md")
        md_file = MdUtils(file_name=report_file, title="Smart Contract Vulnerability Report")
        
        # Add metadata
        contract_name = self.analysis.get('contract_name', 'Unknown Contract')
        contract_hash = self.analysis.get('contract_hash', 'Unknown')
        
        md_file.new_header(level=1, title=f"Security Analysis: {contract_name}")
        
        # Add generation info
        md_file.new_paragraph(f"**Contract Hash**: {contract_hash}")
        md_file.new_paragraph(f"**Report Generated**: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        md_file.new_paragraph(f"**Analysis Contributors**: {self.analysis.get('total_miners', 0)} miners")
        
        # Add executive summary
        md_file.new_header(level=2, title="Executive Summary")
        md_file.new_paragraph(executive_summary)
        
        # Add risk score
        risk_score = self.analysis.get('risk_score', 0)
        md_file.new_header(level=2, title="Risk Assessment")
        
        # Create risk score text representation
        risk_text = "█" * int(risk_score) + "░" * (10 - int(risk_score))
        md_file.new_paragraph(f"Risk Score: **{risk_score}/10** [{risk_text}]")
        
        # Risk level description
        if risk_score >= 7.5:
            risk_level = "Critical Risk"
        elif risk_score >= 5:
            risk_level = "High Risk"
        elif risk_score >= 2.5:
            risk_level = "Medium Risk"
        else:
            risk_level = "Low Risk"
            
        md_file.new_paragraph(f"Risk Level: **{risk_level}**")
        
        # Add charts if available
        if charts:
            md_file.new_header(level=2, title="Vulnerability Distribution")
            
            if 'severity_chart' in charts:
                md_file.new_paragraph("### Severity Distribution")
                md_file.new_paragraph(md_file.new_inline_image(
                    text="Severity Distribution", 
                    path=os.path.basename(charts['severity_chart'])
                ))
            
            if 'consensus_chart' in charts:
                md_file.new_paragraph("### Top Vulnerabilities by Consensus")
                md_file.new_paragraph(md_file.new_inline_image(
                    text="Consensus Distribution", 
                    path=os.path.basename(charts['consensus_chart'])
                ))
        
        # Add vulnerability details
        md_file.new_header(level=2, title="Vulnerability Details")
        
        # Group vulnerabilities by severity
        severity_groups = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }
        
        for vuln in self.analysis.get('vulnerabilities', []):
            severity = vuln.get('calculated_severity', 'low')
            if severity in severity_groups:
                severity_groups[severity].append(vuln)
        
        # Add each vulnerability by severity group
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            vulns = severity_groups[severity]
            if not vulns:
                continue
                
            md_file.new_header(level=3, title=f"{severity.capitalize()} Severity Vulnerabilities")
            
            for i, vuln in enumerate(vulns, 1):
                vuln_type = vuln.get('type', 'Unknown Vulnerability')
                consensus = vuln.get('confidence_percent', '0%')
                
                md_file.new_header(level=4, title=f"{i}. {vuln_type}")
                
                # Add vulnerability metadata
                md_file.new_paragraph(f"**Consensus**: {consensus} of miners agree")
                md_file.new_paragraph(f"**Affected Lines**: {', '.join(map(str, vuln.get('line_numbers', [])))} ")
                
                # Add enhanced description if available
                description = vuln.get('enhanced_description', vuln.get('description', 'No description available.'))
                md_file.new_paragraph(description)
                
                # Add code snippet if available
                code_snippet = vuln.get('code_snippet', '')
                if code_snippet:
                    md_file.new_paragraph("**Vulnerable Code:**")
                    md_file.insert_code(code_snippet, language='solidity')
        
        # Save markdown file
        md_file.create_md_file()
        
        return report_file
    
    def generate_html_report(self, executive_summary, charts=None):
        """
        Generate an HTML report.
        
        Args:
            executive_summary (str): Executive summary text
            charts (dict, optional): Paths to chart images
            
        Returns:
            str: Path to generated report
        """
        # Load HTML template
        template = self.template_env.get_template('report_template.html')
        
        # Prepare template variables
        contract_name = self.analysis.get('contract_name', 'Unknown Contract')
        contract_hash = self.analysis.get('contract_hash', 'Unknown')
        risk_score = self.analysis.get('risk_score', 0)
        
        # Group vulnerabilities by severity
        severity_groups = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }
        
        for vuln in self.analysis.get('vulnerabilities', []):
            severity = vuln.get('calculated_severity', 'low')
            if severity in severity_groups:
                severity_groups[severity].append(vuln)
        
        # Prepare chart paths for template
        chart_paths = {}
        if charts:
            for chart_name, chart_path in charts.items():
                chart_paths[chart_name] = os.path.basename(chart_path)
        
        # Render template
        html_content = template.render(
            contract_name=contract_name,
            contract_hash=contract_hash,
            timestamp=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            miner_count=self.analysis.get('total_miners', 0),
            executive_summary=executive_summary,
            risk_score=risk_score,
            severity_counts=self.analysis.get('severity_counts', {}),
            severity_groups=severity_groups,
            charts=chart_paths
        )
        
        # Write HTML file
        html_report_path = os.path.join(self.output_dir, f"{self.base_filename}_report.html")
        with open(html_report_path, 'w') as f:
            f.write(html_content)
        
        return html_report_path
    
    def generate_json_report(self):
        """
        Generate a JSON report.
        
        Returns:
            str: Path to generated report
        """
        # Create a simplified version for JSON export
        report_data = {
            'metadata': {
                'contract_name': self.analysis.get('contract_name', 'Unknown Contract'),
                'contract_hash': self.analysis.get('contract_hash', 'Unknown'),
                'generated_at': datetime.datetime.now().isoformat(),
                'miner_count': self.analysis.get('total_miners', 0)
            },
            'summary': {
                'risk_score': self.analysis.get('risk_score', 0),
                'vulnerability_count': self.analysis.get('vulnerability_count', 0),
                'severity_counts': self.analysis.get('severity_counts', {})
            },
            'vulnerabilities': self.analysis.get('vulnerabilities', [])
        }
        
        # Write JSON file
        json_report_path = os.path.join(self.output_dir, f"{self.base_filename}_report.json")
        with open(json_report_path, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        return json_report_path
    
    def generate_all_reports(self, executive_summary):
        """
        Generate all report formats.
        
        Args:
            executive_summary (str): Executive summary text
            
        Returns:
            dict: Paths to all generated reports
        """
        # Generate charts first
        charts = self.generate_charts()
        
        # Generate all report formats
        markdown_report = self.generate_markdown_report(executive_summary, charts)
        html_report = self.generate_html_report(executive_summary, charts)
        json_report = self.generate_json_report()
        
        return {
            'markdown': markdown_report,
            'html': html_report,
            'json': json_report,
            'charts': charts
        }