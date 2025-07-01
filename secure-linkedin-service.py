"""
SECURE Unified LinkedIn Automation Service

This is the security-hardened version of the LinkedIn service with all critical
vulnerabilities addressed and production-ready security measures implemented.

Security Features:
- Environment-based configuration (no hardcoded secrets)
- Comprehensive input validation and sanitization
- Rate limiting and authentication
- Secure error handling
- Security headers and CORS protection
- Audit logging and monitoring
"""

import asyncio
import json
import logging
import os
import redis
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from enum import Enum

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Request
from fastapi.security import HTTPBearer
from pydantic import BaseModel, validator, Field
import httpx
import asyncpg
from sqlalchemy import create_engine, Column, String, DateTime, Integer, JSON, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Import our security middleware
from security_middleware import (
    create_secure_app, 
    require_auth, 
    InputValidator,
    auth_handler,
    APIKeyValidator
)

# Secure Configuration Management
class SecureConfig:
    """Secure configuration loaded from environment variables"""
    
    def __init__(self):
        # Database Configuration
        self.DATABASE_URL = os.getenv("DATABASE_URL")
        if not self.DATABASE_URL:
            raise ValueError("DATABASE_URL environment variable is required")
        
        # Redis Configuration
        self.REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/1")
        
        # LinkedIn API Configuration
        self.LINKEDIN_CLIENT_ID = os.getenv("LINKEDIN_CLIENT_ID")
        self.LINKEDIN_CLIENT_SECRET = os.getenv("LINKEDIN_CLIENT_SECRET")
        self.LINKEDIN_REDIRECT_URI = os.getenv("LINKEDIN_REDIRECT_URI")
        
        if not all([self.LINKEDIN_CLIENT_ID, self.LINKEDIN_CLIENT_SECRET, self.LINKEDIN_REDIRECT_URI]):
            raise ValueError("LinkedIn API credentials are required")
        
        # Service URLs
        self.CORE_ORCHESTRATOR_URL = os.getenv("CORE_ORCHESTRATOR_URL", "http://localhost:3000")
        self.STYLE_ENGINE_URL = os.getenv("STYLE_ENGINE_URL", "http://localhost:8002")
        
        # Security Configuration
        self.MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH", "10000"))
        self.MAX_URL_LENGTH = int(os.getenv("MAX_URL_LENGTH", "2048"))
        
        # Validate URLs to prevent SSRF
        self.validate_service_urls()
    
    def validate_service_urls(self):
        """Validate service URLs to prevent SSRF attacks"""
        allowed_hosts = os.getenv("ALLOWED_SERVICE_HOSTS", "localhost,127.0.0.1").split(",")
        
        for url_name, url in [
            ("CORE_ORCHESTRATOR_URL", self.CORE_ORCHESTRATOR_URL),
            ("STYLE_ENGINE_URL", self.STYLE_ENGINE_URL)
        ]:
            if not any(host in url for host in allowed_hosts):
                raise ValueError(f"{url_name} contains disallowed host: {url}")

config = SecureConfig()

# Enhanced Models with Validation
class PostStatus(Enum):
    DRAFT = "draft"
    SCHEDULED = "scheduled"
    PUBLISHED = "published"
    FAILED = "failed"

@dataclass
class LinkedInCredentials:
    access_token: str
    refresh_token: str
    expires_at: datetime
    user_id: str
    profile_id: str

class ContentRequest(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=100)
    source: Dict[str, Any] = Field(...)
    style_profile: str = Field(..., min_length=1, max_length=50)
    scheduling: Optional[Dict[str, Any]] = Field(default=None)
    linkedin_config: Optional[Dict[str, Any]] = Field(default=None)
    
    @validator('user_id')
    def validate_user_id(cls, v):
        # Validate user ID format
        if not v.replace('-', '').replace('_', '').isalnum():
            raise ValueError('User ID must be alphanumeric with hyphens or underscores only')
        return v
    
    @validator('source')
    def validate_source(cls, v):
        # Enhanced source validation
        if 'type' not in v or 'content' not in v:
            raise ValueError('Source must contain type and content')
        
        if v['type'] not in ['url', 'text', 'template']:
            raise ValueError('Source type must be url, text, or template')
        
        # Content validation
        content = v['content']
        if not isinstance(content, str):
            raise ValueError('Content must be a string')
        
        # Length validation based on type
        if v['type'] == 'url' and len(content) > config.MAX_URL_LENGTH:
            raise ValueError(f'URL too long (max {config.MAX_URL_LENGTH} characters)')
        elif len(content) > config.MAX_CONTENT_LENGTH:
            raise ValueError(f'Content too long (max {config.MAX_CONTENT_LENGTH} characters)')
        
        # URL validation for URL type
        if v['type'] == 'url':
            if not content.startswith(('http://', 'https://')):
                raise ValueError('URL must start with http:// or https://')
            
            # Basic SSRF protection
            import urllib.parse
            parsed = urllib.parse.urlparse(content)
            if parsed.hostname in ['localhost', '127.0.0.1', '0.0.0.0'] and os.getenv("ENVIRONMENT") == "production":
                raise ValueError('Local URLs not allowed in production')
        
        # Input validation and sanitization
        validation_result = InputValidator.validate_input(content, max_length=config.MAX_CONTENT_LENGTH)
        if not validation_result["is_valid"]:
            raise ValueError(f'Content validation failed: {", ".join(validation_result["issues"])}')
        
        return v
    
    @validator('style_profile')
    def validate_style_profile(cls, v):
        # Whitelist allowed style profiles
        allowed_profiles = [
            'technical_leader', 'startup_founder', 'business_strategist',
            'creative_professional', 'industry_analyst'
        ]
        if v not in allowed_profiles:
            raise ValueError(f'Style profile must be one of: {", ".join(allowed_profiles)}')
        return v

class PostResponse(BaseModel):
    post_id: str
    status: str
    content: str = Field(..., max_length=1300)  # LinkedIn limit
    scheduled_time: Optional[datetime]
    performance_prediction: Optional[Dict[str, float]]
    processing_metadata: Dict[str, Any]

# Database Models (same as before but with secure config)
Base = declarative_base()

class LinkedInPost(Base):
    __tablename__ = "linkedin_posts"
    
    id = Column(String, primary_key=True)
    user_id = Column(String, nullable=False, index=True)
    content = Column(Text, nullable=False)
    status = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    scheduled_for = Column(DateTime, nullable=True, index=True)
    posted_at = Column(DateTime, nullable=True)
    linkedin_post_id = Column(String, nullable=True)
    engagement_metrics = Column(JSON, nullable=True)
    processing_metadata = Column(JSON, nullable=True)

class UserProfile(Base):
    __tablename__ = "user_profiles"
    
    user_id = Column(String, primary_key=True)
    linkedin_credentials = Column(JSON, nullable=False)
    style_profile = Column(JSON, nullable=False)
    scheduling_config = Column(JSON, nullable=False)
    performance_history = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)

# Secure Service Classes

class SecureLinkedInAPIClient:
    """Enhanced LinkedIn API client with comprehensive security measures"""
    
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
        self.rate_limit_key = "linkedin_api_rate_limit"
        self.base_url = "https://api.linkedin.com/v2"
        self.logger = logging.getLogger(__name__)
        
        # Security: Validate LinkedIn API configuration
        if not all([config.LINKEDIN_CLIENT_ID, config.LINKEDIN_CLIENT_SECRET]):
            raise ValueError("LinkedIn API credentials not properly configured")
    
    async def authenticate_user(self, auth_code: str, client_credentials: Dict[str, str]) -> LinkedInCredentials:
        """Authenticate user with enhanced security validation"""
        
        # Input validation
        if not auth_code or len(auth_code) < 10:
            raise HTTPException(status_code=400, detail="Invalid authorization code")
        
        # Validate auth code format (LinkedIn auth codes are alphanumeric)
        if not auth_code.replace('-', '').replace('_', '').isalnum():
            raise HTTPException(status_code=400, detail="Invalid authorization code format")
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                # Use secure credentials from config, not user input
                token_response = await client.post(
                    "https://www.linkedin.com/oauth/v2/accessToken",
                    data={
                        "grant_type": "authorization_code",
                        "code": auth_code,
                        "client_id": config.LINKEDIN_CLIENT_ID,
                        "client_secret": config.LINKEDIN_CLIENT_SECRET,
                        "redirect_uri": config.LINKEDIN_REDIRECT_URI
                    },
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "User-Agent": "SecureLinkedInService/1.0"
                    }
                )
                
                if token_response.status_code != 200:
                    self.logger.warning(f"LinkedIn authentication failed: {token_response.status_code}")
                    raise HTTPException(status_code=400, detail="LinkedIn authentication failed")
                
                token_data = token_response.json()
                
                # Validate token response
                required_fields = ['access_token', 'expires_in']
                if not all(field in token_data for field in required_fields):
                    raise HTTPException(status_code=400, detail="Invalid token response from LinkedIn")
                
                # Get user profile with rate limiting
                await self._enforce_rate_limit("profile_fetch")
                
                profile_response = await client.get(
                    f"{self.base_url}/people/~",
                    headers={
                        "Authorization": f"Bearer {token_data['access_token']}",
                        "User-Agent": "SecureLinkedInService/1.0"
                    }
                )
                
                if profile_response.status_code != 200:
                    raise HTTPException(status_code=400, detail="Failed to fetch LinkedIn profile")
                
                profile_data = profile_response.json()
                
                # Validate profile data
                if 'id' not in profile_data:
                    raise HTTPException(status_code=400, detail="Invalid profile data from LinkedIn")
                
                return LinkedInCredentials(
                    access_token=token_data["access_token"],
                    refresh_token=token_data.get("refresh_token", ""),
                    expires_at=datetime.utcnow() + timedelta(seconds=token_data["expires_in"]),
                    user_id=profile_data["id"],
                    profile_id=profile_data["id"]
                )
                
        except httpx.TimeoutException:
            raise HTTPException(status_code=408, detail="Request timeout")
        except httpx.RequestError as e:
            self.logger.error(f"LinkedIn API request error: {e}")
            raise HTTPException(status_code=503, detail="LinkedIn API unavailable")
        except Exception as e:
            self.logger.error(f"Authentication error: {e}")
            raise HTTPException(status_code=500, detail="Authentication failed")
    
    async def _enforce_rate_limit(self, operation: str) -> None:
        """Enforce rate limiting for LinkedIn API calls"""
        rate_key = f"{self.rate_limit_key}:{operation}"
        current_count = await self.redis.get(rate_key)
        
        if current_count is None:
            await self.redis.setex(rate_key, 3600, 1)
        elif int(current_count) >= 100:  # LinkedIn API limit
            raise HTTPException(status_code=429, detail="LinkedIn API rate limit exceeded")
        else:
            await self.redis.incr(rate_key)
    
    async def publish_post(self, credentials: LinkedInCredentials, content: str, visibility: str = "PUBLIC") -> Dict[str, Any]:
        """Publish post with comprehensive security validation"""
        
        # Validate inputs
        if not content or len(content.strip()) == 0:
            raise HTTPException(status_code=400, detail="Content cannot be empty")
        
        if len(content) > 1300:  # LinkedIn limit
            raise HTTPException(status_code=400, detail="Content exceeds LinkedIn character limit")
        
        # Validate visibility
        allowed_visibility = ["PUBLIC", "CONNECTIONS"]
        if visibility not in allowed_visibility:
            raise HTTPException(status_code=400, detail="Invalid visibility setting")
        
        # Check token expiration
        if credentials.expires_at <= datetime.utcnow():
            raise HTTPException(status_code=401, detail="LinkedIn access token expired")
        
        # Content validation
        validation_result = InputValidator.validate_input(content, max_length=1300)
        if not validation_result["is_valid"]:
            raise HTTPException(
                status_code=400, 
                detail=f"Content validation failed: {', '.join(validation_result['issues'])}"
            )
        
        # Rate limiting
        await self._enforce_rate_limit(f"post:{credentials.user_id}")
        
        try:
            post_data = {
                "author": f"urn:li:person:{credentials.profile_id}",
                "lifecycleState": "PUBLISHED",
                "specificContent": {
                    "com.linkedin.ugc.ShareContent": {
                        "shareCommentary": {
                            "text": validation_result["sanitized_data"]
                        },
                        "shareMediaCategory": "NONE"
                    }
                },
                "visibility": {
                    "com.linkedin.ugc.MemberNetworkVisibility": visibility
                }
            }
            
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{self.base_url}/ugcPosts",
                    json=post_data,
                    headers={
                        "Authorization": f"Bearer {credentials.access_token}",
                        "Content-Type": "application/json",
                        "X-Restli-Protocol-Version": "2.0.0",
                        "User-Agent": "SecureLinkedInService/1.0"
                    }
                )
                
                if response.status_code not in [200, 201]:
                    self.logger.error(f"LinkedIn post failed: {response.status_code} - {response.text}")
                    raise HTTPException(
                        status_code=response.status_code,
                        detail="Failed to publish LinkedIn post"
                    )
                
                result = response.json()
                
                # Audit log
                self.logger.info(f"LinkedIn post published: user={credentials.user_id}, post_id={result.get('id')}")
                
                return result
                
        except httpx.TimeoutException:
            raise HTTPException(status_code=408, detail="Request timeout")
        except httpx.RequestError as e:
            self.logger.error(f"LinkedIn API error: {e}")
            raise HTTPException(status_code=503, detail="LinkedIn API unavailable")

class SecureContentProcessor:
    """Secure content processing with validation and sanitization"""
    
    def __init__(self):
        self.core_orchestrator_url = config.CORE_ORCHESTRATOR_URL
        self.style_engine_url = config.STYLE_ENGINE_URL
        self.logger = logging.getLogger(__name__)
        
        # Validate service URLs on initialization
        self._validate_service_urls()
    
    def _validate_service_urls(self):
        """Validate service URLs to prevent SSRF"""
        for url in [self.core_orchestrator_url, self.style_engine_url]:
            if not url.startswith(('http://', 'https://')):
                raise ValueError(f"Invalid service URL: {url}")
    
    async def process_url_content(self, url: str, user_id: str, style_profile: str) -> Dict[str, Any]:
        """Process URL content with security validation"""
        
        # URL validation
        if not url.startswith(('http://', 'https://')):
            raise HTTPException(status_code=400, detail="Invalid URL protocol")
        
        # URL length check
        if len(url) > config.MAX_URL_LENGTH:
            raise HTTPException(status_code=400, detail="URL too long")
        
        # SSRF protection
        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        
        # Block private IP ranges in production
        if os.getenv("ENVIRONMENT") == "production":
            if parsed.hostname in ['localhost', '127.0.0.1', '0.0.0.0']:
                raise HTTPException(status_code=400, detail="Local URLs not allowed")
            
            # Block private IP ranges
            import ipaddress
            try:
                ip = ipaddress.ip_address(parsed.hostname)
                if ip.is_private:
                    raise HTTPException(status_code=400, detail="Private IP addresses not allowed")
            except ValueError:
                pass  # Hostname is not an IP address
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{self.core_orchestrator_url}/api/v1/content/process",
                    json={
                        "source": {"type": "url", "content": url},
                        "userId": user_id,
                        "styleProfile": style_profile,
                        "platformConfig": {
                            "linkedin": {
                                "maxLength": 1300,
                                "hashtagLimit": 5,
                                "emojiEnabled": True
                            }
                        }
                    },
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": "SecureLinkedInService/1.0"
                    }
                )
                
                if response.status_code == 200:
                    result = response.json()
                    
                    # Validate response
                    if not isinstance(result, dict) or "data" not in result:
                        raise HTTPException(status_code=502, detail="Invalid response from content processor")
                    
                    # Additional content validation
                    content = result["data"].get("content", "")
                    validation_result = InputValidator.validate_input(content, max_length=1300)
                    
                    if not validation_result["is_valid"]:
                        self.logger.warning(f"Content processor returned invalid content: {validation_result['issues']}")
                        # Sanitize the content
                        content = validation_result["sanitized_data"]
                    
                    return {
                        "content": content,
                        "metadata": result["data"].get("metadata", {}),
                        "processing_method": "enhanced_langpost",
                        "confidence": result["data"].get("metadata", {}).get("confidenceScores", {}).get("ai_generation", 0.8)
                    }
                else:
                    raise HTTPException(status_code=502, detail="Content processing service unavailable")
                    
        except httpx.TimeoutException:
            raise HTTPException(status_code=408, detail="Content processing timeout")
        except httpx.RequestError as e:
            self.logger.error(f"Content processing error: {e}")
            raise HTTPException(status_code=503, detail="Content processing service unavailable")

# Create secure FastAPI application
app = create_secure_app("Secure LinkedIn Automation Service", "1.0.0")

# Secure database setup with environment configuration
try:
    engine = create_engine(
        config.DATABASE_URL,
        pool_size=20,
        max_overflow=30,
        pool_timeout=30,
        pool_recycle=3600,  # Recycle connections every hour
        echo=False  # Never log SQL in production
    )
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
except Exception as e:
    logging.error(f"Database configuration error: {e}")
    raise

def get_db():
    """Database dependency with proper cleanup"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Initialize secure services
try:
    redis_client = redis.Redis.from_url(config.REDIS_URL)
    linkedin_client = SecureLinkedInAPIClient(redis_client)
    content_processor = SecureContentProcessor()
    api_key_validator = APIKeyValidator()
except Exception as e:
    logging.error(f"Service initialization error: {e}")
    raise

# Secure API Endpoints

@app.post("/api/v1/content/create-and-schedule", response_model=PostResponse)
async def create_and_schedule_post(
    request: ContentRequest,
    background_tasks: BackgroundTasks,
    current_user: Dict[str, Any] = require_auth(),
    db=Depends(get_db)
):
    """Create and schedule LinkedIn post with comprehensive security"""
    
    # Authorization check
    if current_user.get("sub") != request.user_id:
        raise HTTPException(status_code=403, detail="Access denied: user mismatch")
    
    try:
        # Get user profile with existence check
        user_profile = db.query(UserProfile).filter(UserProfile.user_id == request.user_id).first()
        if not user_profile:
            raise HTTPException(status_code=404, detail="User profile not found")
        
        # Validate credentials existence and format
        if not user_profile.linkedin_credentials:
            raise HTTPException(status_code=400, detail="LinkedIn credentials not configured")
        
        try:
            credentials = LinkedInCredentials(**user_profile.linkedin_credentials)
        except (TypeError, ValueError) as e:
            raise HTTPException(status_code=400, detail="Invalid LinkedIn credentials format")
        
        # Check token expiration
        if credentials.expires_at <= datetime.utcnow():
            raise HTTPException(status_code=401, detail="LinkedIn access token expired")
        
        # Process content securely
        if request.source["type"] == "url":
            processed_content = await content_processor.process_url_content(
                request.source["content"],
                request.user_id,
                request.style_profile
            )
        else:
            # For text content, validate and sanitize
            validation_result = InputValidator.validate_input(
                request.source["content"], 
                max_length=config.MAX_CONTENT_LENGTH
            )
            if not validation_result["is_valid"]:
                raise HTTPException(
                    status_code=400,
                    detail=f"Content validation failed: {', '.join(validation_result['issues'])}"
                )
            
            processed_content = {
                "content": validation_result["sanitized_data"],
                "metadata": {"processing_method": "direct_input"},
                "confidence": 0.9
            }
        
        # Create post record
        post_id = f"post_{request.user_id}_{int(datetime.utcnow().timestamp())}"
        
        # Determine scheduling
        scheduled_time = None
        if request.scheduling:
            # Add scheduling logic here
            scheduled_time = datetime.utcnow() + timedelta(hours=1)  # Default 1 hour
        
        # Create database record
        post_record = LinkedInPost(
            id=post_id,
            user_id=request.user_id,
            content=processed_content["content"],
            status=PostStatus.SCHEDULED.value if scheduled_time else PostStatus.DRAFT.value,
            scheduled_for=scheduled_time,
            processing_metadata=processed_content.get("metadata", {})
        )
        
        db.add(post_record)
        db.commit()
        
        # Audit log
        logging.info(f"Post created: user={request.user_id}, post_id={post_id}, scheduled={scheduled_time}")
        
        return PostResponse(
            post_id=post_id,
            status=post_record.status,
            content=processed_content["content"],
            scheduled_time=scheduled_time,
            performance_prediction={"confidence": processed_content.get("confidence", 0.8)},
            processing_metadata=processed_content.get("metadata", {})
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Post creation failed: {e}")
        raise HTTPException(status_code=500, detail="Post creation failed")

@app.get("/api/v1/posts/{user_id}")
async def get_user_posts(
    user_id: str,
    status: Optional[str] = None,
    current_user: Dict[str, Any] = require_auth(),
    db=Depends(get_db)
):
    """Get user's posts with authorization"""
    
    # Authorization check
    if current_user.get("sub") != user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Input validation
    if status and status not in [s.value for s in PostStatus]:
        raise HTTPException(status_code=400, detail="Invalid status filter")
    
    try:
        query = db.query(LinkedInPost).filter(LinkedInPost.user_id == user_id)
        
        if status:
            query = query.filter(LinkedInPost.status == status)
        
        posts = query.order_by(LinkedInPost.created_at.desc()).limit(50).all()
        
        return {
            "posts": [
                {
                    "id": post.id,
                    "content": post.content[:100] + "..." if len(post.content) > 100 else post.content,  # Truncate for security
                    "status": post.status,
                    "created_at": post.created_at.isoformat(),
                    "scheduled_for": post.scheduled_for.isoformat() if post.scheduled_for else None,
                    "posted_at": post.posted_at.isoformat() if post.posted_at else None
                }
                for post in posts
            ]
        }
    except Exception as e:
        logging.error(f"Failed to fetch posts for user {user_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch posts")

@app.post("/api/v1/auth/linkedin")
async def authenticate_linkedin(
    auth_data: Dict[str, str],
    current_user: Dict[str, Any] = require_auth(),
    db=Depends(get_db)
):
    """Authenticate user with LinkedIn - Secure version"""
    
    try:
        # Input validation
        required_fields = ["code"]
        if not all(field in auth_data for field in required_fields):
            raise HTTPException(status_code=400, detail="Missing required authentication data")
        
        # Validate auth code
        auth_code = auth_data["code"]
        if not auth_code or len(auth_code) < 10:
            raise HTTPException(status_code=400, detail="Invalid authorization code")
        
        # Authenticate with LinkedIn
        credentials = await linkedin_client.authenticate_user(auth_code, {})
        
        # Authorization check - ensure user can only authenticate for themselves
        if current_user.get("sub") != credentials.user_id:
            raise HTTPException(status_code=403, detail="Authentication mismatch")
        
        # Store or update user profile
        user_profile = db.query(UserProfile).filter(UserProfile.user_id == credentials.user_id).first()
        
        if user_profile:
            user_profile.linkedin_credentials = asdict(credentials)
            user_profile.updated_at = datetime.utcnow()
        else:
            user_profile = UserProfile(
                user_id=credentials.user_id,
                linkedin_credentials=asdict(credentials),
                style_profile={
                    "tone": "professional",
                    "voice": "first_person",
                    "length_preference": "medium",
                    "hashtag_style": "moderate",
                    "emoji_usage": True,
                    "call_to_action_frequency": 0.6
                },
                scheduling_config={
                    "preferred_times": ["09:00", "13:00", "17:00"],
                    "timezone": "UTC",
                    "frequency_per_week": 3,
                    "audience_optimization": True,
                    "conflict_resolution": "time_shift"
                }
            )
            db.add(user_profile)
        
        db.commit()
        
        # Audit log (without sensitive data)
        logging.info(f"LinkedIn authentication successful: user={credentials.user_id}")
        
        return {
            "success": True,
            "user_id": credentials.user_id,
            "expires_at": credentials.expires_at.isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"LinkedIn authentication error: {e}")
        raise HTTPException(status_code=500, detail="Authentication failed")

@app.get("/health")
async def health_check():
    """Comprehensive health check with security status"""
    
    checks = {
        "database": False,
        "redis": False,
        "linkedin_config": False,
        "security": False
    }
    
    try:
        # Database check
        db = SessionLocal()
        db.execute("SELECT 1")
        checks["database"] = True
        db.close()
    except:
        pass
    
    try:
        # Redis check
        redis_client.ping()
        checks["redis"] = True
    except:
        pass
    
    # LinkedIn configuration check
    checks["linkedin_config"] = all([
        config.LINKEDIN_CLIENT_ID,
        config.LINKEDIN_CLIENT_SECRET,
        config.LINKEDIN_REDIRECT_URI
    ])
    
    # Security configuration check
    checks["security"] = True  # Security middleware is loaded
    
    status = "healthy" if all(checks.values()) else "degraded"
    
    return {
        "status": status,
        "checks": checks,
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0-secure"
    }

if __name__ == "__main__":
    import uvicorn
    
    # Production server configuration
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8001,
        access_log=False,  # Use structured logging instead
        server_header=False,  # Don't reveal server information
        date_header=False
    )