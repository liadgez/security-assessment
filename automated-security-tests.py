#!/usr/bin/env python3
"""
Automated Security Testing Suite for Unified Social Media AI Platform

This script performs comprehensive automated security testing including:
- Static Application Security Testing (SAST)
- Dynamic Application Security Testing (DAST)
- Configuration security checks
- API security testing
- Input validation testing
"""

import os
import json
import subprocess
import asyncio
import logging
import tempfile
import shutil
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import aiohttp
import bandit
from bandit.core import manager as bandit_manager
from bandit.core import config as bandit_config

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class SecurityTestResult:
    """Security test result"""
    test_name: str
    test_type: str  # SAST, DAST, CONFIG, API
    severity: str   # CRITICAL, HIGH, MEDIUM, LOW, INFO
    status: str     # PASS, FAIL, SKIP, ERROR
    description: str
    details: Dict[str, Any]
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    recommendation: Optional[str] = None

@dataclass 
class SecurityTestSuite:
    """Complete security test suite results"""
    scan_date: str
    total_tests: int
    passed_tests: int
    failed_tests: int
    skipped_tests: int
    critical_issues: int
    high_issues: int
    medium_issues: int
    low_issues: int
    results: List[SecurityTestResult]
    summary_recommendations: List[str]

class SecurityTester:
    """Comprehensive automated security testing"""
    
    def __init__(self, project_root: str):
        self.project_root = project_root
        self.test_results = []
        self.api_base_urls = {
            "linkedin": "http://localhost:8001",
            "style": "http://localhost:8002", 
            "analytics": "http://localhost:8003",
            "core": "http://localhost:3000"
        }
    
    async def run_all_tests(self) -> SecurityTestSuite:
        """Run all security tests"""
        logger.info("Starting comprehensive security test suite...")
        
        # Run different test categories
        await self.run_sast_tests()
        await self.run_configuration_tests()
        await self.run_api_security_tests()
        await self.run_input_validation_tests()
        await self.run_authentication_tests()
        
        # Generate summary
        return self._generate_test_summary()
    
    async def run_sast_tests(self) -> None:
        """Run Static Application Security Testing"""
        logger.info("Running SAST tests...")
        
        # Bandit scan for Python files
        await self._run_bandit_scan()
        
        # Custom security pattern checks
        await self._run_custom_security_checks()
        
        # Secret detection
        await self._run_secret_detection()
    
    async def _run_bandit_scan(self) -> None:
        """Run Bandit security scanner"""
        try:
            # Find Python files
            python_files = []
            for root, dirs, files in os.walk(self.project_root):
                # Skip test directories and virtual environments
                if any(skip in root for skip in ['test', 'venv', '.git', '__pycache__']):
                    continue
                for file in files:
                    if file.endswith('.py'):
                        python_files.append(os.path.join(root, file))
            
            if not python_files:
                self.test_results.append(SecurityTestResult(
                    test_name="bandit_scan",
                    test_type="SAST",
                    severity="INFO",
                    status="SKIP",
                    description="No Python files found to scan",
                    details={}
                ))
                return
            
            # Run Bandit programmatically
            for py_file in python_files[:20]:  # Limit to first 20 files for demo
                try:
                    # Create Bandit manager
                    conf = bandit_config.BanditConfig()
                    b_mgr = bandit_manager.BanditManager(conf, 'file')
                    
                    # Scan file
                    b_mgr.discover_files([py_file])
                    b_mgr.run_tests()
                    
                    # Process results
                    for issue in b_mgr.get_issue_list():
                        severity_map = {'LOW': 'LOW', 'MEDIUM': 'MEDIUM', 'HIGH': 'HIGH'}
                        
                        self.test_results.append(SecurityTestResult(
                            test_name=f"bandit_{issue.test_id}",
                            test_type="SAST",
                            severity=severity_map.get(issue.severity, 'MEDIUM'),
                            status="FAIL",
                            description=f"Bandit {issue.test_id}: {issue.text}",
                            details={
                                "test_id": issue.test_id,
                                "confidence": issue.confidence,
                                "more_info": getattr(issue, 'more_info', '')
                            },
                            file_path=issue.fname,
                            line_number=issue.lineno,
                            recommendation=f"Review and fix {issue.test_id} security issue"
                        ))
                
                except Exception as e:
                    logger.warning(f"Bandit scan failed for {py_file}: {e}")
                    
        except Exception as e:
            logger.error(f"Bandit scan setup failed: {e}")
            self.test_results.append(SecurityTestResult(
                test_name="bandit_scan",
                test_type="SAST", 
                severity="HIGH",
                status="ERROR",
                description=f"Bandit scan failed: {str(e)}",
                details={"error": str(e)}
            ))
    
    async def _run_custom_security_checks(self) -> None:
        """Run custom security pattern checks"""
        
        security_patterns = {
            "hardcoded_secrets": [
                r"password\s*=\s*[\"'][^\"']{8,}[\"']",
                r"api[_-]?key\s*=\s*[\"'][^\"']{20,}[\"']",
                r"secret\s*=\s*[\"'][^\"']{16,}[\"']",
                r"token\s*=\s*[\"'][^\"']{20,}[\"']"
            ],
            "sql_injection": [
                r"\.execute\s*\(\s*[\"'].*%.*[\"']",
                r"\.format\s*\(.*\)\s*\)",
                r"f[\"'].*\{.*\}.*[\"'].*execute"
            ],
            "command_injection": [
                r"os\.system\s*\(",
                r"subprocess\.(call|run|Popen).*shell\s*=\s*True",
                r"eval\s*\(",
                r"exec\s*\("
            ],
            "weak_crypto": [
                r"md5\s*\(",
                r"sha1\s*\(",
                r"DES\(",
                r"RC4\("
            ]
        }
        
        # Scan all Python files
        for root, dirs, files in os.walk(self.project_root):
            if any(skip in root for skip in ['test', 'venv', '.git', '__pycache__']):
                continue
                
            for file in files:
                if file.endswith('.py'):
                    file_path = os.path.join(root, file)
                    await self._check_file_for_patterns(file_path, security_patterns)
    
    async def _check_file_for_patterns(self, file_path: str, patterns: Dict[str, List[str]]) -> None:
        """Check file for security patterns"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
            
            import re
            for pattern_type, pattern_list in patterns.items():
                for pattern in pattern_list:
                    for line_num, line in enumerate(lines, 1):
                        if re.search(pattern, line, re.IGNORECASE):
                            severity = "HIGH" if pattern_type in ["hardcoded_secrets", "sql_injection", "command_injection"] else "MEDIUM"
                            
                            self.test_results.append(SecurityTestResult(
                                test_name=f"pattern_{pattern_type}",
                                test_type="SAST",
                                severity=severity,
                                status="FAIL",
                                description=f"Potential {pattern_type.replace('_', ' ')} detected",
                                details={
                                    "pattern": pattern,
                                    "line_content": line.strip()
                                },
                                file_path=file_path,
                                line_number=line_num,
                                recommendation=f"Review and remediate {pattern_type.replace('_', ' ')}"
                            ))
                            
        except Exception as e:
            logger.warning(f"Failed to scan {file_path}: {e}")
    
    async def _run_secret_detection(self) -> None:
        """Run secret detection scan"""
        
        secret_patterns = {
            "aws_access_key": r"AKIA[0-9A-Z]{16}",
            "aws_secret_key": r"[0-9a-zA-Z/+]{40}",
            "github_token": r"ghp_[0-9a-zA-Z]{36}",
            "openai_api_key": r"sk-[0-9a-zA-Z]{48}",
            "linkedin_client_secret": r"[0-9a-zA-Z]{16}",
            "jwt_secret": r"[0-9a-zA-Z]{32,}",
            "database_url": r"postgresql://[^:]+:[^@]+@[^/]+/[^\\s]+",
            "private_key": r"-----BEGIN.*PRIVATE KEY-----"
        }
        
        # Scan all text files
        for root, dirs, files in os.walk(self.project_root):
            if any(skip in root for skip in ['.git', '__pycache__', 'node_modules']):
                continue
                
            for file in files:
                if file.endswith(('.py', '.js', '.ts', '.json', '.env', '.txt', '.md', '.yml', '.yaml')):
                    file_path = os.path.join(root, file)
                    await self._check_file_for_secrets(file_path, secret_patterns)
    
    async def _check_file_for_secrets(self, file_path: str, patterns: Dict[str, str]) -> None:
        """Check file for secrets"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            import re
            for secret_type, pattern in patterns.items():
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    self.test_results.append(SecurityTestResult(
                        test_name=f"secret_{secret_type}",
                        test_type="SAST",
                        severity="CRITICAL",
                        status="FAIL",
                        description=f"Potential {secret_type.replace('_', ' ')} found",
                        details={
                            "pattern_type": secret_type,
                            "matches_count": len(matches)
                        },
                        file_path=file_path,
                        recommendation="Remove secrets from code and use environment variables"
                    ))
                    
        except Exception as e:
            logger.warning(f"Failed to scan {file_path} for secrets: {e}")
    
    async def run_configuration_tests(self) -> None:
        """Run configuration security tests"""
        logger.info("Running configuration security tests...")
        
        # Check for secure configuration files
        await self._check_cors_configuration()
        await self._check_database_configuration()
        await self._check_authentication_configuration()
        await self._check_logging_configuration()
    
    async def _check_cors_configuration(self) -> None:
        """Check CORS configuration"""
        
        cors_files = []
        for root, dirs, files in os.walk(self.project_root):
            for file in files:
                if file.endswith('.py'):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r') as f:
                            content = f.read()
                            if 'CORSMiddleware' in content or 'allow_origins' in content:
                                cors_files.append(file_path)
                    except:
                        pass
        
        for file_path in cors_files:
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                
                # Check for wildcard CORS
                if 'allow_origins=["*"]' in content or "allow_origins=['*']" in content:
                    self.test_results.append(SecurityTestResult(
                        test_name="cors_wildcard",
                        test_type="CONFIG",
                        severity="CRITICAL",
                        status="FAIL",
                        description="CORS configured with wildcard origin (*)",
                        details={"file": file_path},
                        file_path=file_path,
                        recommendation="Replace wildcard with specific allowed origins"
                    ))
                
                # Check for permissive CORS
                if 'allow_credentials=True' in content and ('allow_origins=["*"]' in content):
                    self.test_results.append(SecurityTestResult(
                        test_name="cors_credentials_wildcard",
                        test_type="CONFIG",
                        severity="CRITICAL",
                        status="FAIL",
                        description="CORS allows credentials with wildcard origin",
                        details={"file": file_path},
                        file_path=file_path,
                        recommendation="Never use allow_credentials=True with wildcard origins"
                    ))
                    
            except Exception as e:
                logger.warning(f"Failed to check CORS in {file_path}: {e}")
    
    async def _check_database_configuration(self) -> None:
        """Check database security configuration"""
        
        # Check for hardcoded database credentials
        db_patterns = [
            r"postgresql://[^:]+:[^@]+@",
            r"mysql://[^:]+:[^@]+@",
            r"mongodb://[^:]+:[^@]+@"
        ]
        
        for root, dirs, files in os.walk(self.project_root):
            for file in files:
                if file.endswith(('.py', '.js', '.ts', '.json')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r') as f:
                            content = f.read()
                            
                        import re
                        for pattern in db_patterns:
                            if re.search(pattern, content):
                                self.test_results.append(SecurityTestResult(
                                    test_name="hardcoded_db_credentials",
                                    test_type="CONFIG", 
                                    severity="CRITICAL",
                                    status="FAIL",
                                    description="Hardcoded database credentials found",
                                    details={"file": file_path},
                                    file_path=file_path,
                                    recommendation="Use environment variables for database credentials"
                                ))
                                
                    except Exception as e:
                        logger.warning(f"Failed to check database config in {file_path}: {e}")
    
    async def _check_authentication_configuration(self) -> None:
        """Check authentication configuration"""
        
        # Look for authentication-related files
        auth_issues = []
        
        for root, dirs, files in os.walk(self.project_root):
            for file in files:
                if file.endswith('.py'):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r') as f:
                            content = f.read()
                            
                        # Check for weak JWT secrets
                        if 'JWT_SECRET' in content or 'SECRET_KEY' in content:
                            if 'change-this' in content.lower() or 'secret' in content.lower():
                                self.test_results.append(SecurityTestResult(
                                    test_name="weak_jwt_secret",
                                    test_type="CONFIG",
                                    severity="CRITICAL", 
                                    status="FAIL",
                                    description="Weak or default JWT secret detected",
                                    details={"file": file_path},
                                    file_path=file_path,
                                    recommendation="Use strong, randomly generated JWT secrets"
                                ))
                        
                        # Check for missing authentication
                        if '@app.post' in content or '@app.get' in content:
                            if 'require_auth' not in content and 'Depends(' not in content:
                                # This might be an unprotected endpoint
                                lines = content.split('\n')
                                for i, line in enumerate(lines):
                                    if '@app.' in line and ('post' in line or 'put' in line or 'delete' in line):
                                        if i + 5 < len(lines):
                                            endpoint_block = '\n'.join(lines[i:i+5])
                                            if 'require_auth' not in endpoint_block:
                                                self.test_results.append(SecurityTestResult(
                                                    test_name="unprotected_endpoint",
                                                    test_type="CONFIG",
                                                    severity="HIGH",
                                                    status="FAIL", 
                                                    description="Potentially unprotected API endpoint",
                                                    details={"file": file_path, "line": i+1},
                                                    file_path=file_path,
                                                    line_number=i+1,
                                                    recommendation="Add authentication to sensitive endpoints"
                                                ))
                                                break
                        
                    except Exception as e:
                        logger.warning(f"Failed to check auth config in {file_path}: {e}")
    
    async def _check_logging_configuration(self) -> None:
        """Check logging security configuration"""
        
        for root, dirs, files in os.walk(self.project_root):
            for file in files:
                if file.endswith('.py'):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r') as f:
                            content = f.read()
                            
                        # Check for sensitive data logging
                        sensitive_patterns = [
                            r'log.*password',
                            r'log.*secret',
                            r'log.*token',
                            r'print.*password',
                            r'print.*secret'
                        ]
                        
                        import re
                        lines = content.split('\n')
                        for line_num, line in enumerate(lines, 1):
                            for pattern in sensitive_patterns:
                                if re.search(pattern, line, re.IGNORECASE):
                                    self.test_results.append(SecurityTestResult(
                                        test_name="sensitive_data_logging",
                                        test_type="CONFIG",
                                        severity="MEDIUM",
                                        status="FAIL",
                                        description="Potential sensitive data logging",
                                        details={"line_content": line.strip()},
                                        file_path=file_path,
                                        line_number=line_num,
                                        recommendation="Sanitize sensitive data before logging"
                                    ))
                                    
                    except Exception as e:
                        logger.warning(f"Failed to check logging in {file_path}: {e}")
    
    async def run_api_security_tests(self) -> None:
        """Run API security tests"""
        logger.info("Running API security tests...")
        
        for service_name, base_url in self.api_base_urls.items():
            await self._test_api_endpoints(service_name, base_url)
    
    async def _test_api_endpoints(self, service_name: str, base_url: str) -> None:
        """Test API endpoints for security issues"""
        
        # Common endpoints to test
        test_endpoints = [
            ("/health", "GET"),
            ("/docs", "GET"),
            ("/api/v1/", "GET"),
            ("/admin", "GET"),
            ("/.env", "GET"),
            ("/config", "GET")
        ]
        
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
            for endpoint, method in test_endpoints:
                try:
                    url = f"{base_url}{endpoint}"
                    
                    if method == "GET":
                        async with session.get(url) as response:
                            await self._analyze_api_response(service_name, endpoint, response)
                    elif method == "POST":
                        async with session.post(url, json={}) as response:
                            await self._analyze_api_response(service_name, endpoint, response)
                            
                except Exception as e:
                    # Service might not be running - skip
                    if "Connection" in str(e):
                        self.test_results.append(SecurityTestResult(
                            test_name=f"api_{service_name}_connection",
                            test_type="API",
                            severity="INFO",
                            status="SKIP",
                            description=f"{service_name} service not running",
                            details={"url": base_url, "error": str(e)}
                        ))
                    continue
    
    async def _analyze_api_response(self, service_name: str, endpoint: str, response: aiohttp.ClientResponse) -> None:
        """Analyze API response for security issues"""
        
        # Check for information disclosure
        if response.status == 200 and endpoint in ["/.env", "/config"]:
            self.test_results.append(SecurityTestResult(
                test_name=f"api_{service_name}_info_disclosure",
                test_type="API",
                severity="CRITICAL",
                status="FAIL",
                description=f"Sensitive endpoint {endpoint} accessible",
                details={"status": response.status, "url": str(response.url)},
                recommendation="Block access to sensitive configuration endpoints"
            ))
        
        # Check security headers
        headers = response.headers
        
        security_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": ["DENY", "SAMEORIGIN"],
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": None,
            "Content-Security-Policy": None
        }
        
        for header_name, expected_value in security_headers.items():
            if header_name not in headers:
                self.test_results.append(SecurityTestResult(
                    test_name=f"api_{service_name}_missing_header",
                    test_type="API",
                    severity="MEDIUM",
                    status="FAIL", 
                    description=f"Missing security header: {header_name}",
                    details={"endpoint": endpoint, "missing_header": header_name},
                    recommendation=f"Add {header_name} security header"
                ))
        
        # Check for server information disclosure
        if "Server" in headers:
            self.test_results.append(SecurityTestResult(
                test_name=f"api_{service_name}_server_disclosure",
                test_type="API",
                severity="LOW",
                status="FAIL",
                description="Server header reveals server information",
                details={"server": headers["Server"]},
                recommendation="Remove or obfuscate Server header"
            ))
    
    async def run_input_validation_tests(self) -> None:
        """Run input validation tests"""
        logger.info("Running input validation tests...")
        
        # Test common injection payloads
        injection_payloads = {
            "sql_injection": [
                "' OR '1'='1",
                "'; DROP TABLE users; --",
                "1' UNION SELECT * FROM users--"
            ],
            "xss": [
                "<script>alert('xss')</script>",
                "javascript:alert('xss')",
                "<img src=x onerror=alert('xss')>"
            ],
            "command_injection": [
                "; ls -la",
                "| cat /etc/passwd",
                "&& whoami"
            ]
        }
        
        # Test each service
        for service_name, base_url in self.api_base_urls.items():
            await self._test_input_validation(service_name, base_url, injection_payloads)
    
    async def _test_input_validation(self, service_name: str, base_url: str, payloads: Dict[str, List[str]]) -> None:
        """Test input validation with malicious payloads"""
        
        # Common POST endpoints to test
        test_endpoints = [
            "/api/v1/content/create-and-schedule",
            "/api/v1/style/transfer", 
            "/api/v1/analytics/comprehensive"
        ]
        
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
            for endpoint in test_endpoints:
                for payload_type, payload_list in payloads.items():
                    for payload in payload_list[:1]:  # Test first payload only for demo
                        try:
                            url = f"{base_url}{endpoint}"
                            
                            # Create test payload
                            test_data = {
                                "user_id": payload,
                                "content": payload,
                                "source": {"type": "text", "content": payload}
                            }
                            
                            async with session.post(url, json=test_data) as response:
                                response_text = await response.text()
                                
                                # Check if payload is reflected in response
                                if payload in response_text and response.status != 400:
                                    self.test_results.append(SecurityTestResult(
                                        test_name=f"input_{service_name}_{payload_type}",
                                        test_type="API",
                                        severity="HIGH",
                                        status="FAIL",
                                        description=f"Potential {payload_type.replace('_', ' ')} vulnerability",
                                        details={
                                            "endpoint": endpoint,
                                            "payload": payload,
                                            "status": response.status
                                        },
                                        recommendation=f"Implement proper input validation for {payload_type.replace('_', ' ')}"
                                    ))
                                
                        except Exception:
                            # Service not running or other error - skip
                            continue
    
    async def run_authentication_tests(self) -> None:
        """Run authentication and authorization tests"""
        logger.info("Running authentication tests...")
        
        # Test for unprotected endpoints
        sensitive_endpoints = [
            "/api/v1/content/create-and-schedule",
            "/api/v1/posts/",
            "/api/v1/auth/linkedin"
        ]
        
        for service_name, base_url in self.api_base_urls.items():
            await self._test_authentication(service_name, base_url, sensitive_endpoints)
    
    async def _test_authentication(self, service_name: str, base_url: str, endpoints: List[str]) -> None:
        """Test authentication requirements"""
        
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
            for endpoint in endpoints:
                try:
                    url = f"{base_url}{endpoint}"
                    
                    # Test without authentication
                    async with session.get(url) as response:
                        if response.status == 200:
                            self.test_results.append(SecurityTestResult(
                                test_name=f"auth_{service_name}_unprotected",
                                test_type="API",
                                severity="HIGH",
                                status="FAIL",
                                description=f"Sensitive endpoint accessible without authentication",
                                details={"endpoint": endpoint, "status": response.status},
                                recommendation="Implement authentication for sensitive endpoints"
                            ))
                        elif response.status == 401:
                            self.test_results.append(SecurityTestResult(
                                test_name=f"auth_{service_name}_protected",
                                test_type="API",
                                severity="INFO",
                                status="PASS",
                                description=f"Endpoint properly protected with authentication",
                                details={"endpoint": endpoint, "status": response.status}
                            ))
                            
                except Exception:
                    # Service not running - skip
                    continue
    
    def _generate_test_summary(self) -> SecurityTestSuite:
        """Generate test summary"""
        
        total_tests = len(self.test_results)
        passed_tests = len([r for r in self.test_results if r.status == "PASS"])
        failed_tests = len([r for r in self.test_results if r.status == "FAIL"])
        skipped_tests = len([r for r in self.test_results if r.status == "SKIP"])
        
        # Count by severity
        severity_counts = {
            "CRITICAL": len([r for r in self.test_results if r.severity == "CRITICAL"]),
            "HIGH": len([r for r in self.test_results if r.severity == "HIGH"]),
            "MEDIUM": len([r for r in self.test_results if r.severity == "MEDIUM"]),
            "LOW": len([r for r in self.test_results if r.severity == "LOW"])
        }
        
        # Generate recommendations
        recommendations = self._generate_summary_recommendations()
        
        return SecurityTestSuite(
            scan_date=datetime.now().isoformat(),
            total_tests=total_tests,
            passed_tests=passed_tests,
            failed_tests=failed_tests,
            skipped_tests=skipped_tests,
            critical_issues=severity_counts["CRITICAL"],
            high_issues=severity_counts["HIGH"], 
            medium_issues=severity_counts["MEDIUM"],
            low_issues=severity_counts["LOW"],
            results=self.test_results,
            summary_recommendations=recommendations
        )
    
    def _generate_summary_recommendations(self) -> List[str]:
        """Generate summary recommendations"""
        recommendations = []
        
        # Count critical issues
        critical_issues = [r for r in self.test_results if r.severity == "CRITICAL" and r.status == "FAIL"]
        if critical_issues:
            recommendations.append(f"🚨 URGENT: Fix {len(critical_issues)} critical security issues immediately")
        
        # Common issue types
        cors_issues = [r for r in self.test_results if "cors" in r.test_name.lower()]
        if cors_issues:
            recommendations.append("🔒 Update CORS configuration to use specific origins")
        
        secret_issues = [r for r in self.test_results if "secret" in r.test_name.lower()]
        if secret_issues:
            recommendations.append("🔑 Remove hardcoded secrets and use environment variables")
        
        auth_issues = [r for r in self.test_results if "auth" in r.test_name.lower() and r.status == "FAIL"]
        if auth_issues:
            recommendations.append("🛡️ Implement proper authentication and authorization")
        
        recommendations.extend([
            "📋 Implement automated security testing in CI/CD pipeline",
            "🔍 Regular security code reviews",
            "📚 Security training for development team"
        ])
        
        return recommendations

def main():
    """Main function"""
    import sys
    
    project_root = sys.argv[1] if len(sys.argv) > 1 else "/Users/liadgez/Documents/technologia"
    
    if not os.path.exists(project_root):
        print(f"Error: Project root '{project_root}' does not exist")
        sys.exit(1)
    
    async def run_tests():
        tester = SecurityTester(project_root)
        results = await tester.run_all_tests()
        
        # Print summary
        print("\n" + "="*60)
        print("🔐 AUTOMATED SECURITY TEST RESULTS")
        print("="*60)
        print(f"📅 Scan Date: {results.scan_date}")
        print(f"🧪 Total Tests: {results.total_tests}")
        print(f"✅ Passed: {results.passed_tests}")
        print(f"❌ Failed: {results.failed_tests}")
        print(f"⏭️  Skipped: {results.skipped_tests}")
        print()
        
        print("📊 SECURITY ISSUES BY SEVERITY:")
        print(f"  🔴 Critical: {results.critical_issues}")
        print(f"  🟠 High:     {results.high_issues}")
        print(f"  🟡 Medium:   {results.medium_issues}")
        print(f"  🟢 Low:      {results.low_issues}")
        print()
        
        if results.failed_tests > 0:
            print("🚨 FAILED TESTS:")
            failed_results = [r for r in results.results if r.status == "FAIL"]
            for i, result in enumerate(failed_results[:10], 1):  # Top 10
                print(f"  {i}. {result.test_name} - {result.severity}")
                print(f"     📝 {result.description}")
                if result.recommendation:
                    print(f"     💡 {result.recommendation}")
                print()
        
        print("💡 SUMMARY RECOMMENDATIONS:")
        for i, rec in enumerate(results.summary_recommendations, 1):
            print(f"  {i}. {rec}")
        
        # Save results
        output_file = os.path.join(project_root, "security-assessment", "security-test-results.json")
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(asdict(results), f, indent=2, default=str)
        
        print(f"\n📄 Detailed results saved to: {output_file}")
        print("="*60)
        
        # Exit with appropriate code
        if results.critical_issues > 0:
            sys.exit(2)
        elif results.high_issues > 0:
            sys.exit(1)
        else:
            sys.exit(0)
    
    # Run async tests
    asyncio.run(run_tests())

if __name__ == "__main__":
    main()