"""
Security Middleware for Unified Social Media AI Platform

This module provides comprehensive security middleware for all FastAPI services
including authentication, rate limiting, input validation, and security headers.
"""

import os
import time
import hmac
import hashlib
import logging
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from functools import wraps
from collections import defaultdict, deque

from fastapi import FastAPI, Request, Response, HTTPException, Depends
from fastapi.middleware.base import BaseHTTPMiddleware
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.sessions import SessionMiddleware
import jwt
from pydantic import BaseModel, validator
import redis

# Configuration
class SecurityConfig:
    """Security configuration loaded from environment variables"""
    
    def __init__(self):
        self.SECRET_KEY = os.getenv("SECRET_KEY", "change-this-secret-key-in-production")
        self.JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "change-this-jwt-secret-too")
        self.ALGORITHM = os.getenv("ALGORITHM", "HS256")
        self.ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
        
        # CORS Configuration
        self.ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")
        self.ALLOWED_METHODS = os.getenv("ALLOWED_METHODS", "GET,POST,PUT,DELETE").split(",")
        self.ALLOWED_HEADERS = os.getenv("ALLOWED_HEADERS", "Content-Type,Authorization,X-API-Key").split(",")
        
        # Rate Limiting
        self.RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))
        self.RATE_LIMIT_PER_HOUR = int(os.getenv("RATE_LIMIT_PER_HOUR", "1000"))
        
        # Security Headers
        self.CSP = os.getenv("CONTENT_SECURITY_POLICY", "default-src 'self'")
        self.X_FRAME_OPTIONS = os.getenv("X_FRAME_OPTIONS", "DENY")
        self.X_CONTENT_TYPE_OPTIONS = os.getenv("X_CONTENT_TYPE_OPTIONS", "nosniff")
        self.HSTS = os.getenv("STRICT_TRANSPORT_SECURITY", "max-age=31536000; includeSubDomains")
        
        # Redis for rate limiting and sessions
        self.REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# Global security configuration
security_config = SecurityConfig()

# Rate Limiting
class RateLimiter:
    """Redis-based distributed rate limiter"""
    
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
        self.logger = logging.getLogger(__name__)
    
    async def is_allowed(self, key: str, limit: int, window: int) -> bool:
        """Check if request is within rate limit"""
        try:
            current_time = int(time.time())
            window_start = current_time - window
            
            # Use Redis sorted set for sliding window
            pipe = self.redis.pipeline()
            pipe.zremrangebyscore(key, 0, window_start)
            pipe.zadd(key, {str(current_time): current_time})
            pipe.zcount(key, window_start, current_time)
            pipe.expire(key, window)
            
            results = pipe.execute()
            request_count = results[2]
            
            return request_count <= limit
            
        except Exception as e:
            self.logger.error(f"Rate limiting error: {e}")
            return True  # Fail open for availability

# Input Validation and Sanitization
class InputValidator:
    """Comprehensive input validation and sanitization"""
    
    # Common dangerous patterns
    SQL_INJECTION_PATTERNS = [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)",
        r"(\b(OR|AND)\s+\d+\s*=\s*\d+)",
        r"(\b(OR|AND)\s+[\"'].*[\"']\s*=\s*[\"'].*[\"'])",
        r"(--|#|\/\*|\*\/)",
        r"(\bxp_cmdshell\b|\bsp_executesql\b)"
    ]
    
    XSS_PATTERNS = [
        r"<script[^>]*>.*?</script>",
        r"javascript:",
        r"on\w+\s*=",
        r"<iframe[^>]*>.*?</iframe>",
        r"<object[^>]*>.*?</object>",
        r"<embed[^>]*>.*?</embed>"
    ]
    
    COMMAND_INJECTION_PATTERNS = [
        r"(\b(eval|exec|system|shell_exec|passthru|popen)\b)",
        r"(\$\(.*\))",
        r"(`.*`)",
        r"(\||\&\&|\|\|)",
        r"(;|\n|\r)"
    ]
    
    @classmethod
    def validate_input(cls, input_data: Any, max_length: int = 10000) -> Dict[str, Any]:
        """Validate and sanitize input data"""
        issues = []
        
        if isinstance(input_data, str):
            # Length check
            if len(input_data) > max_length:
                issues.append(f"Input exceeds maximum length of {max_length}")
            
            # SQL injection check
            for pattern in cls.SQL_INJECTION_PATTERNS:
                if re.search(pattern, input_data, re.IGNORECASE):
                    issues.append("Potential SQL injection detected")
                    break
            
            # XSS check
            for pattern in cls.XSS_PATTERNS:
                if re.search(pattern, input_data, re.IGNORECASE):
                    issues.append("Potential XSS payload detected")
                    break
            
            # Command injection check
            for pattern in cls.COMMAND_INJECTION_PATTERNS:
                if re.search(pattern, input_data, re.IGNORECASE):
                    issues.append("Potential command injection detected")
                    break
        
        return {
            "is_valid": len(issues) == 0,
            "issues": issues,
            "sanitized_data": cls.sanitize_input(input_data) if isinstance(input_data, str) else input_data
        }
    
    @classmethod
    def sanitize_input(cls, input_string: str) -> str:
        """Sanitize input string"""
        if not isinstance(input_string, str):
            return input_string
        
        # Remove null bytes
        sanitized = input_string.replace('\x00', '')
        
        # Escape HTML entities
        sanitized = sanitized.replace('<', '&lt;').replace('>', '&gt;')
        sanitized = sanitized.replace('"', '&quot;').replace("'", '&#x27;')
        
        # Remove potentially dangerous characters
        sanitized = re.sub(r'[<>"\']', '', sanitized)
        
        return sanitized

# Authentication and Authorization
class AuthenticationHandler:
    """JWT-based authentication handler"""
    
    def __init__(self):
        self.security = HTTPBearer()
        self.logger = logging.getLogger(__name__)
    
    def create_access_token(self, data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """Create JWT access token"""
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=security_config.ACCESS_TOKEN_EXPIRE_MINUTES)
        
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, security_config.JWT_SECRET_KEY, algorithm=security_config.ALGORITHM)
        return encoded_jwt
    
    def verify_token(self, token: str) -> Dict[str, Any]:
        """Verify JWT token"""
        try:
            payload = jwt.decode(token, security_config.JWT_SECRET_KEY, algorithms=[security_config.ALGORITHM])
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token expired")
        except jwt.JWTError:
            raise HTTPException(status_code=401, detail="Invalid token")
    
    async def get_current_user(self, credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())) -> Dict[str, Any]:
        """Get current authenticated user"""
        token = credentials.credentials
        payload = self.verify_token(token)
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        return payload

# Security Headers Middleware
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses"""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        
        # Security headers
        response.headers["Content-Security-Policy"] = security_config.CSP
        response.headers["X-Frame-Options"] = security_config.X_FRAME_OPTIONS
        response.headers["X-Content-Type-Options"] = security_config.X_CONTENT_TYPE_OPTIONS
        response.headers["Strict-Transport-Security"] = security_config.HSTS
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        
        # Remove server information
        response.headers.pop("Server", None)
        
        return response

# Rate Limiting Middleware
class RateLimitingMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware"""
    
    def __init__(self, app: FastAPI, redis_client: redis.Redis):
        super().__init__(app)
        self.rate_limiter = RateLimiter(redis_client)
        self.logger = logging.getLogger(__name__)
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        client_ip = request.client.host
        
        # Rate limiting keys
        minute_key = f"rate_limit:minute:{client_ip}:{int(time.time() // 60)}"
        hour_key = f"rate_limit:hour:{client_ip}:{int(time.time() // 3600)}"
        
        # Check rate limits
        minute_allowed = await self.rate_limiter.is_allowed(
            minute_key, security_config.RATE_LIMIT_PER_MINUTE, 60
        )
        hour_allowed = await self.rate_limiter.is_allowed(
            hour_key, security_config.RATE_LIMIT_PER_HOUR, 3600
        )
        
        if not minute_allowed:
            raise HTTPException(
                status_code=429, 
                detail="Rate limit exceeded: too many requests per minute"
            )
        
        if not hour_allowed:
            raise HTTPException(
                status_code=429, 
                detail="Rate limit exceeded: too many requests per hour"
            )
        
        response = await call_next(request)
        
        # Add rate limit headers
        response.headers["X-RateLimit-Limit-Minute"] = str(security_config.RATE_LIMIT_PER_MINUTE)
        response.headers["X-RateLimit-Limit-Hour"] = str(security_config.RATE_LIMIT_PER_HOUR)
        response.headers["X-RateLimit-Remaining-Minute"] = str(
            max(0, security_config.RATE_LIMIT_PER_MINUTE - (await self.get_current_count(minute_key)))
        )
        
        return response
    
    async def get_current_count(self, key: str) -> int:
        """Get current request count for rate limiting key"""
        try:
            return await self.rate_limiter.redis.zcount(key, 0, int(time.time()))
        except:
            return 0

# Input Validation Middleware
class InputValidationMiddleware(BaseHTTPMiddleware):
    """Validate all incoming request data"""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip validation for certain endpoints
        skip_paths = ["/health", "/metrics", "/docs", "/openapi.json"]
        if any(request.url.path.startswith(path) for path in skip_paths):
            return await call_next(request)
        
        # Validate request body if present
        if request.method in ["POST", "PUT", "PATCH"]:
            try:
                body = await request.body()
                if body:
                    body_str = body.decode('utf-8')
                    validation_result = InputValidator.validate_input(body_str, max_length=100000)
                    
                    if not validation_result["is_valid"]:
                        self.logger.warning(f"Invalid input detected: {validation_result['issues']}")
                        raise HTTPException(
                            status_code=400,
                            detail=f"Invalid input: {', '.join(validation_result['issues'])}"
                        )
                
                # Rebuild request with validated body
                request._body = body
            except UnicodeDecodeError:
                raise HTTPException(status_code=400, detail="Invalid character encoding")
        
        # Validate query parameters
        for key, value in request.query_params.items():
            validation_result = InputValidator.validate_input(value, max_length=1000)
            if not validation_result["is_valid"]:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid query parameter '{key}': {', '.join(validation_result['issues'])}"
                )
        
        return await call_next(request)

# Error Handling Middleware
class SecureErrorHandlingMiddleware(BaseHTTPMiddleware):
    """Secure error handling to prevent information disclosure"""
    
    def __init__(self, app: FastAPI):
        super().__init__(app)
        self.logger = logging.getLogger(__name__)
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        try:
            response = await call_next(request)
            return response
        except HTTPException as e:
            # Log the actual error
            self.logger.error(f"HTTP Exception: {e.detail} - Path: {request.url.path}")
            
            # Return sanitized error message
            if e.status_code >= 500:
                # Don't expose internal server errors
                sanitized_detail = "Internal server error occurred"
            else:
                # Client errors can show more detail but sanitized
                sanitized_detail = self.sanitize_error_message(str(e.detail))
            
            return Response(
                content=f'{{"error": "{sanitized_detail}"}}',
                status_code=e.status_code,
                headers={"Content-Type": "application/json"}
            )
        except Exception as e:
            # Log the actual error with full details
            self.logger.error(f"Unhandled exception: {str(e)} - Path: {request.url.path}", exc_info=True)
            
            # Return generic error message
            return Response(
                content='{"error": "An unexpected error occurred"}',
                status_code=500,
                headers={"Content-Type": "application/json"}
            )
    
    def sanitize_error_message(self, message: str) -> str:
        """Sanitize error messages to prevent information disclosure"""
        # Remove file paths
        message = re.sub(r'/[a-zA-Z0-9_/.-]+\.py', '[file]', message)
        
        # Remove line numbers
        message = re.sub(r'line \d+', 'line [number]', message)
        
        # Remove database connection details
        message = re.sub(r'postgresql://[^"\']+', 'postgresql://[redacted]', message)
        message = re.sub(r'redis://[^"\']+', 'redis://[redacted]', message)
        
        # Remove internal server names/IPs
        message = re.sub(r'\b\d+\.\d+\.\d+\.\d+\b', '[ip]', message)
        
        return message

# Main security setup function
def setup_security(app: FastAPI, redis_client: redis.Redis) -> None:
    """Setup all security middleware and configurations"""
    
    # CORS with restricted origins
    app.add_middleware(
        CORSMiddleware,
        allow_origins=security_config.ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=security_config.ALLOWED_METHODS,
        allow_headers=security_config.ALLOWED_HEADERS,
    )
    
    # Session middleware
    app.add_middleware(
        SessionMiddleware,
        secret_key=security_config.SECRET_KEY,
        max_age=3600,  # 1 hour
        same_site="strict",
        https_only=os.getenv("ENVIRONMENT") == "production"
    )
    
    # Security middleware in order of execution
    app.add_middleware(SecureErrorHandlingMiddleware)
    app.add_middleware(InputValidationMiddleware)
    app.add_middleware(RateLimitingMiddleware, redis_client=redis_client)
    app.add_middleware(SecurityHeadersMiddleware)

# Authentication dependency
auth_handler = AuthenticationHandler()

def require_auth():
    """Dependency to require authentication"""
    return Depends(auth_handler.get_current_user)

# API Key validation (alternative to JWT)
class APIKeyValidator:
    """API Key based authentication for service-to-service communication"""
    
    def __init__(self):
        self.valid_api_keys = set(os.getenv("VALID_API_KEYS", "").split(","))
        self.logger = logging.getLogger(__name__)
    
    async def validate_api_key(self, request: Request) -> bool:
        """Validate API key from header"""
        api_key = request.headers.get("X-API-Key")
        if not api_key:
            return False
        
        # Constant time comparison to prevent timing attacks
        is_valid = any(
            hmac.compare_digest(api_key.encode(), valid_key.encode()) 
            for valid_key in self.valid_api_keys if valid_key
        )
        
        if not is_valid:
            self.logger.warning(f"Invalid API key attempt from {request.client.host}")
        
        return is_valid

# Secure configuration validation
def validate_security_config() -> List[str]:
    """Validate security configuration and return warnings"""
    warnings = []
    
    if security_config.SECRET_KEY == "change-this-secret-key-in-production":
        warnings.append("SECRET_KEY is using default value - change for production")
    
    if security_config.JWT_SECRET_KEY == "change-this-jwt-secret-too":
        warnings.append("JWT_SECRET_KEY is using default value - change for production")
    
    if len(security_config.SECRET_KEY) < 32:
        warnings.append("SECRET_KEY should be at least 32 characters long")
    
    if "localhost" in security_config.ALLOWED_ORIGINS and os.getenv("ENVIRONMENT") == "production":
        warnings.append("CORS allows localhost in production environment")
    
    return warnings

# Usage example
def create_secure_app(title: str, version: str = "1.0.0") -> FastAPI:
    """Create a FastAPI app with all security configurations"""
    
    # Validate configuration
    warnings = validate_security_config()
    if warnings:
        logging.warning("Security configuration warnings: " + "; ".join(warnings))
    
    # Create app
    app = FastAPI(title=title, version=version)
    
    # Setup Redis for rate limiting
    redis_client = redis.Redis.from_url(security_config.REDIS_URL)
    
    # Setup security
    setup_security(app, redis_client)
    
    return app

# Health check with security information
def get_security_status() -> Dict[str, Any]:
    """Get security status for health checks"""
    return {
        "security_enabled": True,
        "rate_limiting": True,
        "input_validation": True,
        "authentication": True,
        "secure_headers": True,
        "cors_configured": True,
        "environment": os.getenv("ENVIRONMENT", "development")
    }