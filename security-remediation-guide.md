# Security Remediation Guide
**Unified Social Media AI Platform - Production Security Hardening**

## 🚨 CRITICAL PRIORITY FIXES (Implement Immediately)

### 1. Replace Wildcard CORS Configuration

**Issue**: All services use `allow_origins=["*"]` which allows any domain to make requests.

**Current Code**:
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # ❌ CRITICAL VULNERABILITY
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

**Secure Fix**:
```python
# Use environment variable for allowed origins
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,  # ✅ Specific origins only
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],  # ✅ Specific methods
    allow_headers=["Content-Type", "Authorization", "X-API-Key"],  # ✅ Specific headers
)
```

**Environment Configuration**:
```bash
# .env file
ALLOWED_ORIGINS=https://yourdomain.com,https://app.yourdomain.com,https://admin.yourdomain.com
```

### 2. Externalize Database Credentials

**Issue**: Hardcoded database credentials in source code.

**Current Code**:
```python
engine = create_engine("postgresql://user:password@localhost/linkedin_automation")  # ❌ CRITICAL
```

**Secure Fix**:
```python
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable is required")

engine = create_engine(
    DATABASE_URL,  # ✅ From environment
    pool_size=20,
    max_overflow=30,
    pool_timeout=30,
    pool_recycle=3600,
    echo=False  # ✅ Never log SQL in production
)
```

**Environment Configuration**:
```bash
# .env file
DATABASE_URL=postgresql://secure_user:complex_password@db.domain.com:5432/prod_database
```

### 3. Implement Authentication/Authorization

**Issue**: No authentication on API endpoints.

**Secure Implementation**:
```python
from security_middleware import require_auth, APIKeyValidator

# Add authentication dependency
@app.post("/api/v1/content/create-and-schedule")
async def create_and_schedule_post(
    request: ContentRequest,
    current_user: Dict[str, Any] = require_auth(),  # ✅ Require authentication
    db=Depends(get_db)
):
    # Verify user authorization
    if current_user.get("sub") != request.user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # ... rest of endpoint logic
```

### 4. Secure Error Handling

**Issue**: Stack traces and internal details exposed to clients.

**Current Code**:
```python
except Exception as e:
    raise HTTPException(status_code=500, detail=str(e))  # ❌ Information disclosure
```

**Secure Fix**:
```python
except Exception as e:
    logger.error(f"Operation failed: {e}", exc_info=True)  # ✅ Log full details
    raise HTTPException(status_code=500, detail="Internal server error")  # ✅ Generic message
```

### 5. Input Validation and Sanitization

**Issue**: User input not properly validated.

**Secure Implementation**:
```python
from security_middleware import InputValidator

class ContentRequest(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=100)
    content: str = Field(..., min_length=1, max_length=10000)
    
    @validator('content')
    def validate_content(cls, v):
        # Comprehensive input validation
        validation_result = InputValidator.validate_input(v, max_length=10000)
        if not validation_result["is_valid"]:
            raise ValueError(f'Content validation failed: {", ".join(validation_result["issues"])}')
        return validation_result["sanitized_data"]  # ✅ Return sanitized content
```

---

## 🔥 HIGH PRIORITY FIXES (Implement Within 24 Hours)

### 6. Add Rate Limiting

**Implementation**:
```python
from security_middleware import RateLimitingMiddleware

# Add rate limiting middleware
app.add_middleware(RateLimitingMiddleware, redis_client=redis_client)
```

**Configuration**:
```bash
# .env file
RATE_LIMIT_PER_MINUTE=60
RATE_LIMIT_PER_HOUR=1000
RATE_LIMIT_PER_DAY=10000
```

### 7. Implement Security Headers

**Implementation**:
```python
from security_middleware import SecurityHeadersMiddleware

# Add security headers middleware
app.add_middleware(SecurityHeadersMiddleware)
```

**Headers Added**:
- Content-Security-Policy
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- Strict-Transport-Security
- X-XSS-Protection
- Referrer-Policy

### 8. Secure Logging Configuration

**Current Issue**: Potential logging of sensitive data.

**Secure Implementation**:
```python
# Custom log formatter that sanitizes sensitive data
class SanitizingFormatter(logging.Formatter):
    def format(self, record):
        msg = super().format(record)
        # Remove sensitive patterns
        msg = re.sub(r'password["\']?\s*:\s*["\'][^"\']+["\']', 'password: [REDACTED]', msg)
        msg = re.sub(r'token["\']?\s*:\s*["\'][^"\']+["\']', 'token: [REDACTED]', msg)
        msg = re.sub(r'secret["\']?\s*:\s*["\'][^"\']+["\']', 'secret: [REDACTED]', msg)
        return msg

# Configure logger with sanitization
handler = logging.StreamHandler()
handler.setFormatter(SanitizingFormatter())
logger.addHandler(handler)
```

### 9. Secure Service Communication

**Issue**: HTTP calls to services without validation.

**Secure Implementation**:
```python
class SecureServiceClient:
    def __init__(self):
        # Validate service URLs
        allowed_hosts = os.getenv("ALLOWED_SERVICE_HOSTS", "").split(",")
        self.validate_service_urls(allowed_hosts)
    
    async def call_service(self, url: str, data: Dict[str, Any]) -> Dict[str, Any]:
        # URL validation to prevent SSRF
        parsed = urllib.parse.urlparse(url)
        if parsed.hostname not in self.allowed_hosts:
            raise ValueError(f"Service URL not allowed: {url}")
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                url,
                json=data,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "SecureServiceClient/1.0",
                    "X-API-Key": os.getenv("INTERNAL_API_KEY")  # ✅ Service auth
                }
            )
            
            if response.status_code != 200:
                raise HTTPException(status_code=502, detail="Service unavailable")
            
            return response.json()
```

---

## ⚠️ MEDIUM PRIORITY FIXES (Implement Within 1 Week)

### 10. Session Management

**Implementation**:
```python
from starlette.middleware.sessions import SessionMiddleware

app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET_KEY"),
    max_age=3600,  # 1 hour
    same_site="strict",
    https_only=os.getenv("ENVIRONMENT") == "production"
)
```

### 11. Content Security Policy

**Implementation**:
```python
CSP_POLICY = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: https:; "
    "connect-src 'self' https://api.linkedin.com https://api.openai.com; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)

@app.middleware("http")
async def add_csp_header(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = CSP_POLICY
    return response
```

### 12. Audit Logging

**Implementation**:
```python
class AuditLogger:
    def __init__(self):
        self.audit_logger = logging.getLogger("audit")
        
    def log_user_action(self, user_id: str, action: str, details: Dict[str, Any]):
        audit_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": user_id,
            "action": action,
            "details": details,
            "ip_address": request.client.host if request else None
        }
        self.audit_logger.info(json.dumps(audit_entry))

# Usage in endpoints
audit_logger = AuditLogger()

@app.post("/api/v1/content/create-and-schedule")
async def create_and_schedule_post(request: ContentRequest, ...):
    # ... endpoint logic
    
    # Audit log successful actions
    audit_logger.log_user_action(
        user_id=request.user_id,
        action="post_scheduled",
        details={"post_id": post_id, "scheduled_time": scheduled_time}
    )
```

---

## 🔧 IMPLEMENTATION CHECKLIST

### Phase 1: Critical Security Fixes (Day 1)
- [ ] Replace CORS wildcard configuration
- [ ] Externalize all database credentials to environment variables
- [ ] Implement input validation and sanitization
- [ ] Add authentication/authorization to all endpoints
- [ ] Secure error handling to prevent information disclosure

### Phase 2: Security Infrastructure (Days 2-3)
- [ ] Implement rate limiting on all endpoints
- [ ] Add comprehensive security headers
- [ ] Secure logging configuration with sensitive data filtering
- [ ] Implement secure service-to-service communication
- [ ] Add API key authentication for internal services

### Phase 3: Enhanced Security (Week 1)
- [ ] Implement session management
- [ ] Add Content Security Policy
- [ ] Implement comprehensive audit logging
- [ ] Add input length validation
- [ ] Secure external service communications

### Phase 4: Security Monitoring (Week 2)
- [ ] Set up security monitoring and alerting
- [ ] Implement automated security testing in CI/CD
- [ ] Create security incident response procedures
- [ ] Set up log aggregation and analysis
- [ ] Regular security scanning automation

---

## 🛠️ DEPLOYMENT CONFIGURATION

### Production Environment Variables

Create a `.env` file with the following secure configuration:

```bash
# Environment
ENVIRONMENT=production
DEBUG=false

# Database
DATABASE_URL=postgresql://secure_user:${DB_PASSWORD}@db.domain.com:5432/prod_db
DATABASE_POOL_SIZE=20
DATABASE_MAX_OVERFLOW=30

# Redis
REDIS_URL=redis://redis_user:${REDIS_PASSWORD}@redis.domain.com:6379/0
REDIS_SSL=true

# API Keys (use secrets management system)
OPENAI_API_KEY=${OPENAI_API_KEY}
LINKEDIN_CLIENT_ID=${LINKEDIN_CLIENT_ID}
LINKEDIN_CLIENT_SECRET=${LINKEDIN_CLIENT_SECRET}

# Security
SECRET_KEY=${SECRET_KEY}  # Generate with: openssl rand -hex 32
JWT_SECRET_KEY=${JWT_SECRET_KEY}  # Generate with: openssl rand -hex 32
SESSION_SECRET_KEY=${SESSION_SECRET_KEY}  # Generate with: openssl rand -hex 32

# CORS
ALLOWED_ORIGINS=https://yourdomain.com,https://app.yourdomain.com
ALLOWED_METHODS=GET,POST,PUT,DELETE
ALLOWED_HEADERS=Content-Type,Authorization,X-API-Key

# Rate Limiting
RATE_LIMIT_PER_MINUTE=60
RATE_LIMIT_PER_HOUR=1000
RATE_LIMIT_PER_DAY=10000

# Security Headers
CONTENT_SECURITY_POLICY="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
X_FRAME_OPTIONS=DENY
STRICT_TRANSPORT_SECURITY=max-age=31536000; includeSubDomains

# Logging
LOG_LEVEL=INFO
LOG_FORMAT=json
AUDIT_LOG_ENABLED=true

# Service Communication
ALLOWED_SERVICE_HOSTS=core-orchestrator,style-engine,analytics,linkedin-service
INTERNAL_API_KEY=${INTERNAL_API_KEY}  # For service-to-service auth
```

### Docker Security Configuration

```dockerfile
# Use security-hardened base images
FROM python:3.11-slim-bullseye

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Set secure working directory
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Set ownership and permissions
RUN chown -R appuser:appuser /app
RUN chmod -R 755 /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8000

# Security: Remove unnecessary packages and clear cache
RUN apt-get autoremove -y && apt-get clean && rm -rf /var/lib/apt/lists/*

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

# Run application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
```

---

## 📊 SECURITY MONITORING

### Key Security Metrics to Monitor

1. **Authentication Failures**
   - Failed login attempts per user/IP
   - Suspicious authentication patterns
   - Token validation failures

2. **Rate Limiting Events**
   - Rate limit exceeded events
   - Unusual traffic patterns
   - Potential DDoS attempts

3. **Input Validation Failures**
   - Malicious payload attempts
   - SQL injection attempts
   - XSS attack attempts

4. **Security Header Compliance**
   - Missing security headers
   - CSP violations
   - Mixed content warnings

### Alerting Configuration

```python
# Example security alerting
class SecurityMonitor:
    def __init__(self):
        self.alert_thresholds = {
            "failed_auth_per_minute": 10,
            "rate_limit_exceeded_per_hour": 100,
            "sql_injection_attempts": 1,
            "xss_attempts": 1
        }
    
    async def check_security_metrics(self):
        # Check various security metrics and send alerts
        if await self.get_failed_auth_count() > self.alert_thresholds["failed_auth_per_minute"]:
            await self.send_alert("HIGH", "Multiple authentication failures detected")
        
        if await self.get_injection_attempts() > 0:
            await self.send_alert("CRITICAL", "Injection attack attempts detected")
    
    async def send_alert(self, severity: str, message: str):
        # Send alerts via email, Slack, PagerDuty, etc.
        pass
```

---

## 🔍 SECURITY TESTING

### Continuous Security Testing

Add to your CI/CD pipeline:

```yaml
# .github/workflows/security.yml
name: Security Tests

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Run Bandit Security Scan
        run: |
          pip install bandit
          bandit -r . -f json -o bandit-report.json || true
      
      - name: Run Safety Dependency Scan
        run: |
          pip install safety
          safety check --json --output safety-report.json || true
      
      - name: Run Custom Security Tests
        run: |
          python security-assessment/automated-security-tests.py
      
      - name: Upload Security Reports
        uses: actions/upload-artifact@v2
        with:
          name: security-reports
          path: |
            bandit-report.json
            safety-report.json
            security-test-results.json
```

### Manual Security Testing Checklist

- [ ] Test authentication bypass attempts
- [ ] Test authorization escalation
- [ ] Test input validation with various payloads
- [ ] Test rate limiting effectiveness
- [ ] Test error handling for information disclosure
- [ ] Test CORS configuration
- [ ] Test security headers presence
- [ ] Test SSL/TLS configuration
- [ ] Test session management
- [ ] Test file upload security (if applicable)

---

## 📚 SECURITY BEST PRACTICES

### Development Security Guidelines

1. **Secure Coding Practices**
   - Always validate and sanitize user input
   - Use parameterized queries for database operations
   - Implement proper error handling
   - Never log sensitive data
   - Use secure random number generation

2. **Authentication & Authorization**
   - Implement multi-factor authentication where possible
   - Use strong password policies
   - Implement account lockout mechanisms
   - Use secure session management
   - Implement proper role-based access control

3. **Data Protection**
   - Encrypt sensitive data at rest and in transit
   - Use HTTPS for all communications
   - Implement proper key management
   - Regular data backup and recovery testing
   - Data retention and disposal policies

4. **Infrastructure Security**
   - Keep all systems and dependencies up to date
   - Use least privilege principle
   - Regular security audits and penetration testing
   - Implement network segmentation
   - Monitor and log security events

### Security Review Process

1. **Code Review Security Checklist**
   - [ ] Input validation implemented
   - [ ] Output encoding/escaping applied
   - [ ] Authentication and authorization checks
   - [ ] Error handling doesn't leak information
   - [ ] Logging doesn't expose sensitive data
   - [ ] Dependencies are up to date
   - [ ] Security headers implemented
   - [ ] Rate limiting applied

2. **Regular Security Assessments**
   - Weekly automated security scans
   - Monthly dependency vulnerability checks
   - Quarterly manual security reviews
   - Annual penetration testing
   - Continuous security monitoring

---

## 🚀 QUICK START SECURITY IMPLEMENTATION

To quickly implement the most critical security fixes:

1. **Copy the security middleware**:
   ```bash
   cp security-assessment/security-middleware.py merged-implementations/
   ```

2. **Use the secure service template**:
   ```bash
   cp security-assessment/secure-linkedin-service.py merged-implementations/linkedin-automation-service/
   ```

3. **Create environment configuration**:
   ```bash
   cp security-assessment/secure-config-template.env .env
   # Edit .env with your actual values
   ```

4. **Run security tests**:
   ```bash
   cd security-assessment
   python automated-security-tests.py
   ```

5. **Install security dependencies**:
   ```bash
   pip install bandit safety pyjwt cryptography
   ```

This guide provides a comprehensive roadmap for securing the Unified Social Media AI Platform. Implement the critical fixes immediately, followed by the phased approach for complete security hardening.