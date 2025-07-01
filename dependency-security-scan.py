#!/usr/bin/env python3
"""
Dependency Security Scanner for Unified Social Media AI Platform

This script scans all Python and Node.js dependencies for known security vulnerabilities
and provides recommendations for updates and security patches.
"""

import os
import json
import subprocess
import sys
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
import pkg_resources
import requests
from packaging import version

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class VulnerabilityInfo:
    """Information about a specific vulnerability"""
    package_name: str
    installed_version: str
    vulnerability_id: str
    severity: str
    description: str
    affected_versions: str
    fixed_versions: List[str]
    published_date: str
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None

@dataclass
class SecurityScanResult:
    """Complete security scan results"""
    scan_date: str
    total_packages: int
    vulnerable_packages: int
    vulnerabilities: List[VulnerabilityInfo]
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    recommendations: List[str]

class DependencySecurityScanner:
    """Comprehensive dependency security scanner"""
    
    def __init__(self, project_root: str):
        self.project_root = project_root
        self.scan_results = []
        
        # Known vulnerability databases
        self.osv_api_base = "https://api.osv.dev/v1/query"
        self.pypi_api_base = "https://pypi.org/pypi"
        
    def scan_python_dependencies(self) -> List[VulnerabilityInfo]:
        """Scan Python dependencies for vulnerabilities"""
        logger.info("Scanning Python dependencies...")
        
        vulnerabilities = []
        
        # Get installed packages
        try:
            installed_packages = {pkg.project_name.lower(): pkg.version 
                                for pkg in pkg_resources.working_set}
        except Exception as e:
            logger.error(f"Failed to get installed packages: {e}")
            return vulnerabilities
        
        # Check each package for vulnerabilities
        for package_name, package_version in installed_packages.items():
            package_vulns = self._check_python_package_vulnerabilities(package_name, package_version)
            vulnerabilities.extend(package_vulns)
        
        return vulnerabilities
    
    def _check_python_package_vulnerabilities(self, package_name: str, package_version: str) -> List[VulnerabilityInfo]:
        """Check specific Python package for vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Query OSV database
            query_data = {
                "package": {
                    "name": package_name,
                    "ecosystem": "PyPI"
                },
                "version": package_version
            }
            
            response = requests.post(self.osv_api_base, json=query_data, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                vulns = data.get("vulns", [])
                
                for vuln in vulns:
                    # Extract vulnerability information
                    vuln_info = VulnerabilityInfo(
                        package_name=package_name,
                        installed_version=package_version,
                        vulnerability_id=vuln.get("id", ""),
                        severity=self._extract_severity(vuln),
                        description=vuln.get("summary", "No description available"),
                        affected_versions=self._extract_affected_versions(vuln),
                        fixed_versions=self._extract_fixed_versions(vuln),
                        published_date=vuln.get("published", ""),
                        cve_id=self._extract_cve_id(vuln),
                        cvss_score=self._extract_cvss_score(vuln)
                    )
                    vulnerabilities.append(vuln_info)
                    
        except Exception as e:
            logger.warning(f"Failed to check vulnerabilities for {package_name}: {e}")
        
        return vulnerabilities
    
    def scan_requirements_files(self) -> List[VulnerabilityInfo]:
        """Scan requirements.txt files for vulnerabilities"""
        logger.info("Scanning requirements.txt files...")
        
        vulnerabilities = []
        requirements_files = []
        
        # Find all requirements files
        for root, dirs, files in os.walk(self.project_root):
            for file in files:
                if file in ['requirements.txt', 'requirements-dev.txt', 'requirements-prod.txt']:
                    requirements_files.append(os.path.join(root, file))
        
        # Scan each requirements file
        for req_file in requirements_files:
            logger.info(f"Scanning {req_file}")
            file_vulns = self._scan_requirements_file(req_file)
            vulnerabilities.extend(file_vulns)
        
        return vulnerabilities
    
    def _scan_requirements_file(self, file_path: str) -> List[VulnerabilityInfo]:
        """Scan specific requirements file"""
        vulnerabilities = []
        
        try:
            with open(file_path, 'r') as f:
                lines = f.readlines()
            
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Parse package and version
                    if '==' in line:
                        package_name, package_version = line.split('==', 1)
                        package_name = package_name.strip()
                        package_version = package_version.strip()
                        
                        package_vulns = self._check_python_package_vulnerabilities(
                            package_name, package_version
                        )
                        vulnerabilities.extend(package_vulns)
                        
        except Exception as e:
            logger.error(f"Failed to scan {file_path}: {e}")
        
        return vulnerabilities
    
    def scan_nodejs_dependencies(self) -> List[VulnerabilityInfo]:
        """Scan Node.js dependencies for vulnerabilities"""
        logger.info("Scanning Node.js dependencies...")
        
        vulnerabilities = []
        package_json_files = []
        
        # Find package.json files
        for root, dirs, files in os.walk(self.project_root):
            if 'package.json' in files:
                package_json_files.append(os.path.join(root, 'package.json'))
        
        for package_file in package_json_files:
            logger.info(f"Scanning {package_file}")
            file_vulns = self._scan_package_json(package_file)
            vulnerabilities.extend(file_vulns)
        
        return vulnerabilities
    
    def _scan_package_json(self, file_path: str) -> List[VulnerabilityInfo]:
        """Scan package.json for vulnerabilities"""
        vulnerabilities = []
        
        try:
            with open(file_path, 'r') as f:
                package_data = json.load(f)
            
            # Check dependencies
            dependencies = package_data.get('dependencies', {})
            dev_dependencies = package_data.get('devDependencies', {})
            
            all_deps = {**dependencies, **dev_dependencies}
            
            for package_name, package_version in all_deps.items():
                # Clean version string
                package_version = package_version.lstrip('^~>=<')
                
                package_vulns = self._check_npm_package_vulnerabilities(
                    package_name, package_version
                )
                vulnerabilities.extend(package_vulns)
                
        except Exception as e:
            logger.error(f"Failed to scan {file_path}: {e}")
        
        return vulnerabilities
    
    def _check_npm_package_vulnerabilities(self, package_name: str, package_version: str) -> List[VulnerabilityInfo]:
        """Check NPM package for vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Query OSV database for npm
            query_data = {
                "package": {
                    "name": package_name,
                    "ecosystem": "npm"
                },
                "version": package_version
            }
            
            response = requests.post(self.osv_api_base, json=query_data, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                vulns = data.get("vulns", [])
                
                for vuln in vulns:
                    vuln_info = VulnerabilityInfo(
                        package_name=package_name,
                        installed_version=package_version,
                        vulnerability_id=vuln.get("id", ""),
                        severity=self._extract_severity(vuln),
                        description=vuln.get("summary", "No description available"),
                        affected_versions=self._extract_affected_versions(vuln),
                        fixed_versions=self._extract_fixed_versions(vuln),
                        published_date=vuln.get("published", ""),
                        cve_id=self._extract_cve_id(vuln),
                        cvss_score=self._extract_cvss_score(vuln)
                    )
                    vulnerabilities.append(vuln_info)
                    
        except Exception as e:
            logger.warning(f"Failed to check vulnerabilities for {package_name}: {e}")
        
        return vulnerabilities
    
    def _extract_severity(self, vuln_data: Dict[str, Any]) -> str:
        """Extract severity from vulnerability data"""
        severity_mapping = {
            'CRITICAL': 'CRITICAL',
            'HIGH': 'HIGH', 
            'MEDIUM': 'MEDIUM',
            'LOW': 'LOW'
        }
        
        # Check different possible severity fields
        severity = vuln_data.get('database_specific', {}).get('severity')
        if not severity:
            severity = vuln_data.get('severity', {}).get('type')
        if not severity:
            # Try to infer from CVSS score
            cvss_score = self._extract_cvss_score(vuln_data)
            if cvss_score:
                if cvss_score >= 9.0:
                    severity = 'CRITICAL'
                elif cvss_score >= 7.0:
                    severity = 'HIGH'
                elif cvss_score >= 4.0:
                    severity = 'MEDIUM'
                else:
                    severity = 'LOW'
            else:
                severity = 'UNKNOWN'
        
        return severity_mapping.get(severity.upper(), severity)
    
    def _extract_affected_versions(self, vuln_data: Dict[str, Any]) -> str:
        """Extract affected versions from vulnerability data"""
        affected = vuln_data.get('affected', [])
        if affected:
            ranges = affected[0].get('ranges', [])
            if ranges:
                events = ranges[0].get('events', [])
                version_info = []
                for event in events:
                    if 'introduced' in event:
                        version_info.append(f"from {event['introduced']}")
                    if 'fixed' in event:
                        version_info.append(f"until {event['fixed']}")
                return ', '.join(version_info)
        return "Unknown"
    
    def _extract_fixed_versions(self, vuln_data: Dict[str, Any]) -> List[str]:
        """Extract fixed versions from vulnerability data"""
        fixed_versions = []
        affected = vuln_data.get('affected', [])
        
        for item in affected:
            ranges = item.get('ranges', [])
            for range_item in ranges:
                events = range_item.get('events', [])
                for event in events:
                    if 'fixed' in event:
                        fixed_versions.append(event['fixed'])
        
        return fixed_versions
    
    def _extract_cve_id(self, vuln_data: Dict[str, Any]) -> Optional[str]:
        """Extract CVE ID from vulnerability data"""
        aliases = vuln_data.get('aliases', [])
        for alias in aliases:
            if alias.startswith('CVE-'):
                return alias
        return None
    
    def _extract_cvss_score(self, vuln_data: Dict[str, Any]) -> Optional[float]:
        """Extract CVSS score from vulnerability data"""
        severity = vuln_data.get('severity', {})
        if isinstance(severity, list) and severity:
            severity = severity[0]
        
        if isinstance(severity, dict):
            score = severity.get('score')
            if score:
                try:
                    return float(score)
                except (ValueError, TypeError):
                    pass
        
        return None
    
    def run_security_audit(self) -> SecurityScanResult:
        """Run comprehensive security audit"""
        logger.info("Starting comprehensive security audit...")
        
        all_vulnerabilities = []
        
        # Scan Python dependencies
        python_vulns = self.scan_python_dependencies()
        all_vulnerabilities.extend(python_vulns)
        
        # Scan requirements files
        req_vulns = self.scan_requirements_files()
        all_vulnerabilities.extend(req_vulns)
        
        # Scan Node.js dependencies
        nodejs_vulns = self.scan_nodejs_dependencies()
        all_vulnerabilities.extend(nodejs_vulns)
        
        # Count severity levels
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for vuln in all_vulnerabilities:
            severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1
        
        # Generate recommendations
        recommendations = self._generate_recommendations(all_vulnerabilities)
        
        # Create scan result
        result = SecurityScanResult(
            scan_date=datetime.now().isoformat(),
            total_packages=len(set(v.package_name for v in all_vulnerabilities)),
            vulnerable_packages=len(set(v.package_name for v in all_vulnerabilities if all_vulnerabilities)),
            vulnerabilities=all_vulnerabilities,
            critical_count=severity_counts['CRITICAL'],
            high_count=severity_counts['HIGH'],
            medium_count=severity_counts['MEDIUM'],
            low_count=severity_counts['LOW'],
            recommendations=recommendations
        )
        
        return result
    
    def _generate_recommendations(self, vulnerabilities: List[VulnerabilityInfo]) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        if not vulnerabilities:
            recommendations.append("✅ No known vulnerabilities found in dependencies")
            recommendations.append("🔄 Keep dependencies up to date with regular scans")
            return recommendations
        
        # Group by severity
        critical_vulns = [v for v in vulnerabilities if v.severity == 'CRITICAL']
        high_vulns = [v for v in vulnerabilities if v.severity == 'HIGH']
        
        if critical_vulns:
            recommendations.append(f"🚨 URGENT: {len(critical_vulns)} critical vulnerabilities require immediate attention")
            for vuln in critical_vulns[:3]:  # Top 3 critical
                if vuln.fixed_versions:
                    recommendations.append(f"  - Update {vuln.package_name} from {vuln.installed_version} to {vuln.fixed_versions[-1]}")
                else:
                    recommendations.append(f"  - Review {vuln.package_name} {vuln.installed_version} - no fix available yet")
        
        if high_vulns:
            recommendations.append(f"⚠️  HIGH: {len(high_vulns)} high-severity vulnerabilities need attention within 24 hours")
        
        # Package-specific recommendations
        vulnerable_packages = set(v.package_name for v in vulnerabilities)
        for package in list(vulnerable_packages)[:5]:  # Top 5 packages
            package_vulns = [v for v in vulnerabilities if v.package_name == package]
            latest_fixed = None
            for vuln in package_vulns:
                if vuln.fixed_versions:
                    if not latest_fixed or version.parse(vuln.fixed_versions[-1]) > version.parse(latest_fixed):
                        latest_fixed = vuln.fixed_versions[-1]
            
            if latest_fixed:
                recommendations.append(f"📦 Update {package} to version {latest_fixed} or later")
        
        # General recommendations
        recommendations.append("🔍 Run dependency audits regularly (weekly recommended)")
        recommendations.append("🤖 Consider automated dependency update tools (Dependabot, Renovate)")
        recommendations.append("📋 Implement security policies for dependency management")
        
        return recommendations
    
    def save_report(self, result: SecurityScanResult, output_file: str) -> None:
        """Save scan report to file"""
        try:
            with open(output_file, 'w') as f:
                json.dump(asdict(result), f, indent=2, default=str)
            logger.info(f"Security scan report saved to {output_file}")
        except Exception as e:
            logger.error(f"Failed to save report: {e}")
    
    def print_summary(self, result: SecurityScanResult) -> None:
        """Print summary of scan results"""
        print("\n" + "="*60)
        print("🔐 DEPENDENCY SECURITY SCAN SUMMARY")
        print("="*60)
        print(f"📅 Scan Date: {result.scan_date}")
        print(f"📦 Total Packages Scanned: {result.total_packages}")
        print(f"🚨 Vulnerable Packages: {result.vulnerable_packages}")
        print(f"🔴 Total Vulnerabilities: {len(result.vulnerabilities)}")
        print()
        
        print("📊 SEVERITY BREAKDOWN:")
        print(f"  🔴 Critical: {result.critical_count}")
        print(f"  🟠 High:     {result.high_count}")
        print(f"  🟡 Medium:   {result.medium_count}")
        print(f"  🟢 Low:      {result.low_count}")
        print()
        
        if result.vulnerabilities:
            print("🚨 TOP VULNERABILITIES:")
            for i, vuln in enumerate(result.vulnerabilities[:5], 1):
                print(f"  {i}. {vuln.package_name} {vuln.installed_version}")
                print(f"     🔴 {vuln.severity} - {vuln.vulnerability_id}")
                print(f"     📝 {vuln.description[:80]}...")
                if vuln.fixed_versions:
                    print(f"     ✅ Fix: Update to {vuln.fixed_versions[-1]}")
                print()
        
        print("💡 RECOMMENDATIONS:")
        for i, rec in enumerate(result.recommendations[:10], 1):
            print(f"  {i}. {rec}")
        
        print("\n" + "="*60)

def main():
    """Main function to run dependency security scan"""
    
    # Default to current directory if no argument provided
    project_root = sys.argv[1] if len(sys.argv) > 1 else "/Users/liadgez/Documents/technologia"
    
    if not os.path.exists(project_root):
        print(f"Error: Project root '{project_root}' does not exist")
        sys.exit(1)
    
    scanner = DependencySecurityScanner(project_root)
    
    try:
        # Run security audit
        result = scanner.run_security_audit()
        
        # Print summary
        scanner.print_summary(result)
        
        # Save detailed report
        output_file = os.path.join(project_root, "security-assessment", "dependency-scan-report.json")
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        scanner.save_report(result, output_file)
        
        # Exit with appropriate code
        if result.critical_count > 0:
            print("❌ CRITICAL vulnerabilities found - immediate action required!")
            sys.exit(2)
        elif result.high_count > 0:
            print("⚠️  HIGH severity vulnerabilities found - action recommended")
            sys.exit(1)
        else:
            print("✅ No critical or high severity vulnerabilities found")
            sys.exit(0)
            
    except Exception as e:
        logger.error(f"Security scan failed: {e}")
        sys.exit(3)

if __name__ == "__main__":
    main()