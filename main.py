import os
import sys
import argparse
import time
from src.aggregator import ResponseAggregator
from src.analyzer import VulnerabilityAnalyzer
from src.openai_handler import OpenAIHandler
from src.report_generator import ReportGenerator
import config

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Bitsec AutoReporter AI - Generate comprehensive security reports from miner responses')
    
    parser.add_argument('--input', '-i', type=str, default='sample_data',
                        help='Directory containing miner response files (default: sample_data)')
    
    parser.add_argument('--output', '-o', type=str, default=config.OUTPUT_DIR,
                        help=f'Directory to save generated reports (default: {config.OUTPUT_DIR})')
    
    parser.add_argument('--format', '-f', type=str, choices=['all', 'markdown', 'html', 'json'], default='all',
                        help='Report format to generate (default: all)')
    
    parser.add_argument('--enhance', '-e', action='store_true', 
                        help='Enhance vulnerability descriptions using OpenAI')
    
    parser.add_argument('--openai-key', type=str,
                        help='OpenAI API key (overrides environment variable)')
    
    return parser.parse_args()

def main():
    """Main application entry point."""
    # Parse command line arguments
    args = parse_arguments()
    
    # Validate input directory
    if not os.path.isdir(args.input):
        print(f"Error: Input directory '{args.input}' does not exist.")
        return 1
    
    # Ensure output directory exists
    os.makedirs(args.output, exist_ok=True)
    
    print(f"Bitsec AutoReporter AI")
    print(f"=====================")
    print(f"Input directory: {args.input}")
    print(f"Output directory: {args.output}")
    print(f"Report format: {args.format}")
    print(f"Enhance descriptions: {'Yes' if args.enhance else 'No'}")
    print()
    
    # Step 1: Aggregate miner responses
    print("Step 1: Aggregating miner responses...")
    start_time = time.time()
    
    aggregator = ResponseAggregator(args.input)
    miner_count = aggregator.load_miner_responses()
    
    if miner_count == 0:
        print("Error: No miner responses found in the input directory.")
        return 1
    
    print(f"  Found {miner_count} miner responses.")
    
    # Aggregate vulnerabilities
    aggregated_data = aggregator.aggregate_vulnerabilities()
    vulnerability_count = len(aggregated_data.get('vulnerabilities', []))
    
    print(f"  Aggregated {vulnerability_count} unique vulnerabilities.")
    print(f"  Completed in {time.time() - start_time:.2f} seconds.")
    print()
    
    # Step 2: Analyze vulnerabilities
    print("Step 2: Analyzing vulnerabilities...")
    start_time = time.time()
    
    analyzer = VulnerabilityAnalyzer(aggregated_data)
    analysis_result = analyzer.analyze()
    
    risk_score = analysis_result.get('risk_score', 0)
    severity_counts = analysis_result.get('severity_counts', {})
    
    print(f"  Risk score: {risk_score}/10")
    print(f"  Severity distribution:")
    for severity, count in severity_counts.items():
        if count > 0:
            print(f"    - {severity.capitalize()}: {count}")
    
    print(f"  Completed in {time.time() - start_time:.2f} seconds.")
    print()
    
    # Step 3: Enhance descriptions with OpenAI (if enabled)
    if args.enhance:
        print("Step 3: Enhancing vulnerability descriptions...")
        start_time = time.time()
        
        # Initialize OpenAI handler
        openai_key = args.openai_key or config.OPENAI_API_KEY
        if not openai_key:
            print("  Error: OpenAI API key is required for enhancement.")
            print("  Skipping enhancement step.")
        else:
            try:
                openai_handler = OpenAIHandler(openai_key)
                
                # Enhance each vulnerability
                enhanced_vulns = []
                for i, vuln in enumerate(analysis_result.get('vulnerabilities', []), 1):
                    print(f"  Enhancing vulnerability {i}/{vulnerability_count}...")
                    enhanced_vuln = openai_handler.enhance_vulnerability_description(vuln)
                    enhanced_vulns.append(enhanced_vuln)
                
                # Update analysis result
                analysis_result['vulnerabilities'] = enhanced_vulns
                
                # Generate executive summary
                print("  Generating executive summary...")
                executive_summary = openai_handler.generate_report_summary(analysis_result)
                
                print(f"  Completed in {time.time() - start_time:.2f} seconds.")
                
            except Exception as e:
                print(f"  Error enhancing descriptions: {e}")
                print("  Using default descriptions instead.")
                executive_summary = ""
        
        print()
    else:
        # Use a basic executive summary if enhancement is disabled
        executive_summary = f"""
## Executive Summary

The smart contract has been analyzed and found to contain {vulnerability_count} potential vulnerabilities. 
The contract has a risk score of **{risk_score}/10**.

### Vulnerability Distribution
- Critical: {severity_counts.get('critical', 0)}
- High: {severity_counts.get('high', 0)}
- Medium: {severity_counts.get('medium', 0)}
- Low: {severity_counts.get('low', 0)}
- Info: {severity_counts.get('info', 0)}

### Recommendation
Address all critical and high severity issues before deploying this contract.
"""
    
    # Step 4: Generate reports
    print("Step 4: Generating reports...")
    start_time = time.time()
    
    report_generator = ReportGenerator(analysis_result, args.output)
    
    if args.format == 'all':
        reports = report_generator.generate_all_reports(executive_summary)
        print(f"  Generated reports:")
        for format_name, report_path in reports.items():
            if format_name != 'charts':
                print(f"    - {format_name.capitalize()}: {os.path.basename(report_path)}")
    elif args.format == 'markdown':
        charts = report_generator.generate_charts()
        report_path = report_generator.generate_markdown_report(executive_summary, charts)
        print(f"  Generated Markdown report: {os.path.basename(report_path)}")
    elif args.format == 'html':
        charts = report_generator.generate_charts()
        report_path = report_generator.generate_html_report(executive_summary, charts)
        print(f"  Generated HTML report: {os.path.basename(report_path)}")
    elif args.format == 'json':
        report_path = report_generator.generate_json_report()
        print(f"  Generated JSON report: {os.path.basename(report_path)}")
    
    print(f"  Completed in {time.time() - start_time:.2f} seconds.")
    print()
    
    print("Report generation completed successfully!")
    print(f"Reports are available in: {args.output}")
    
    return 0

if __name__ == '__main__':
    sys.exit(main())