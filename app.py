from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Enum, Float, Text, Boolean, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
from sqlalchemy.pool import AsyncAdapterPool
from datetime import datetime
import enum
import logging
import sys
import resource
import tempfile
import shutil
import asyncio
import aiohttp
from pathlib import Path
import json
import aiogit
import signal
from typing import Optional, List, Dict, Any
import os
from pydantic import BaseModel, Field
import uvicorn
from contextlib import asynccontextmanager

# Configure logging with structlog for better output
import structlog

logger = structlog.get_logger()
logging.basicConfig(level=logging.INFO)

# Constants
MEMORY_LIMIT_MB = 256
SCAN_CONCURRENCY = 2
GITLAB_URL = os.getenv('GITLAB_URL', 'https://gitlab.com')
GITLAB_CLIENT_ID = os.getenv('GITLAB_CLIENT_ID')
GITLAB_CLIENT_SECRET = os.getenv('GITLAB_CLIENT_SECRET')
GITLAB_REDIRECT_URI = os.getenv('GITLAB_REDIRECT_URI')
DATABASE_URL = os.getenv('DATABASE_URL')

# Convert SQLAlchemy URL to async
ASYNC_DATABASE_URL = DATABASE_URL.replace('postgresql://', 'postgresql+asyncpg://')

# Models
Base = declarative_base()

class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    SCANNING = "scanning"
    COMPLETED = "completed"
    FAILED = "failed"

class UserRepository(Base):
    __tablename__ = 'user_repositories'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(String, nullable=False, index=True)
    gitlab_project_id = Column(Integer, nullable=False)
    repository_name = Column(String, nullable=False)
    repository_url = Column(String, nullable=False)
    last_scan_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    default_branch = Column(String)
    visibility = Column(String)
    size_mb = Column(Float)
    scan_results = relationship("ScanResult", back_populates="repository")

class ScanResult(Base):
    __tablename__ = 'scan_results'
    
    id = Column(Integer, primary_key=True)
    repository_id = Column(Integer, ForeignKey('user_repositories.id'))
    user_id = Column(String, nullable=False, index=True)
    scan_date = Column(DateTime, default=datetime.utcnow)
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING)
    commit_sha = Column(String)
    branch = Column(String)
    findings_count = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    findings = Column(JSONB)
    error_message = Column(Text)
    duration_seconds = Column(Float)
    files_scanned = Column(Integer)
    files_skipped = Column(Integer)
    repository = relationship("UserRepository", back_populates="scan_results")

# Pydantic models for API
class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    refresh_token: Optional[str]

class UserData(BaseModel):
    id: int
    username: str
    email: Optional[str]

class ScanStatusResponse(BaseModel):
    scan_id: int
    status: ScanStatus
    repository_id: int
    error: Optional[str]
    findings_count: Optional[int]

class RepositoryResponse(BaseModel):
    id: int
    name: str
    url: str
    last_scan: Optional[str]

# Database
class AsyncDatabaseSession:
    def __init__(self):
        self._session = None
        self._engine = None

    def __getattr__(self, name):
        return getattr(self._session, name)

    async def init(self):
        self._engine = create_async_engine(
            ASYNC_DATABASE_URL,
            echo=False,
            pool_size=20,
            max_overflow=10,
            pool_pre_ping=True,
            pool_use_lifo=True
        )
        
        async_session = sessionmaker(
            self._engine, class_=AsyncSession, expire_on_commit=False
        )
        self._session = async_session()

    async def create_all(self):
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def close(self):
        if self._session:
            await self._session.close()
        if self._engine:
            await self._engine.dispose()

db = AsyncDatabaseSession()

# GitLab Integration
class GitLabIntegration:
    def __init__(self):
        self.scan_semaphore = asyncio.Semaphore(SCAN_CONCURRENCY)
        self._session = aiohttp.ClientSession()

    async def close(self):
        if self._session:
            await self._session.close()

    async def verify_token(self, access_token: str) -> UserData:
        async with self._session.get(
            f"{GITLAB_URL}/api/v4/user",
            headers={"Authorization": f"Bearer {access_token}"}
        ) as response:
            if response.status != 200:
                raise HTTPException(status_code=401, detail="Invalid token")
            data = await response.json()
            return UserData(**data)

    async def clone_repository(self, clone_url: str, temp_dir: Path, default_branch: str) -> bool:
        try:
            repo = await aiogit.clone(
                clone_url,
                temp_dir,
                branch=default_branch,
                depth=1,
                single_branch=True
            )
            return True
        except Exception as e:
            logger.error("clone_failed", error=str(e))
            return False

    async def run_semgrep_scan(self, temp_dir: Path) -> tuple[bool, Optional[dict], Optional[str]]:
        try:
            # Set process memory limits
            resource.setrlimit(resource.RLIMIT_AS, (MEMORY_LIMIT_MB * 1024 * 1024, resource.RLIM_INFINITY))
            
            process = await asyncio.create_subprocess_exec(
                "semgrep",
                "scan",
                "--config=auto",
                "--json",
                "--max-memory", str(MEMORY_LIMIT_MB),
                "--timeout", "30",
                str(temp_dir),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60)
                if process.returncode == 0:
                    results = json.loads(stdout)
                    return True, results, None
                return False, None, stderr.decode()
            except asyncio.TimeoutError:
                if process:
                    try:
                        process.kill()
                    except:
                        pass
                return False, None, "Scan timeout exceeded"
        except Exception as e:
            return False, None, str(e)

    async def scan_repository(
        self,
        user_id: str,
        repo_id: int,
        access_token: str,
        gitlab_project_id: int,
        scan_id: int
    ):
        async with self.scan_semaphore:
            logger.info("scan_started", scan_id=scan_id, repo_id=repo_id)
            
            try:
                # Update scan status
                async with db._session.begin():
                    scan = await db._session.get(ScanResult, scan_id)
                    if not scan:
                        return
                    scan.status = ScanStatus.SCANNING
                
                with tempfile.TemporaryDirectory(prefix='scanner_') as temp_dir_str:
                    temp_dir = Path(temp_dir_str)
                    
                    # Get repository info from GitLab
                    async with self._session.get(
                        f"{GITLAB_URL}/api/v4/projects/{gitlab_project_id}",
                        headers={"Authorization": f"Bearer {access_token}"}
                    ) as response:
                        if response.status != 200:
                            raise Exception("Failed to get repository info")
                        project_data = await response.json()
                    
                    # Clone repository
                    clone_url = project_data['http_url_to_repo'].replace(
                        "https://",
                        f"https://oauth2:{access_token}@"
                    )
                    
                    if not await self.clone_repository(clone_url, temp_dir, project_data['default_branch']):
                        raise Exception("Repository clone failed")
                    
                    # Run scan
                    success, results, error = await self.run_semgrep_scan(temp_dir)
                    
                    async with db._session.begin():
                        scan = await db._session.get(ScanResult, scan_id)
                        if success and results:
                            findings = results.get('results', [])[:100]
                            
                            severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
                            for finding in findings:
                                severity = finding.get('extra', {}).get('severity', 'LOW').upper()
                                severity_counts[severity] += 1
                            
                            scan.status = ScanStatus.COMPLETED
                            scan.findings = findings
                            scan.findings_count = len(findings)
                            scan.critical_count = severity_counts['CRITICAL']
                            scan.high_count = severity_counts['HIGH']
                            scan.medium_count = severity_counts['MEDIUM']
                            scan.low_count = severity_counts['LOW']
                            scan.files_scanned = results.get('stats', {}).get('files_scanned', 0)
                        else:
                            scan.status = ScanStatus.FAILED
                            scan.error_message = error
                        
                        repo = await db._session.get(UserRepository, repo_id)
                        if repo:
                            repo.last_scan_at = datetime.utcnow()
            
            except Exception as e:
                logger.error("scan_failed", scan_id=scan_id, error=str(e))
                async with db._session.begin():
                    scan = await db._session.get(ScanResult, scan_id)
                    if scan:
                        scan.status = ScanStatus.FAILED
                        scan.error_message = str(e)

gitlab = GitLabIntegration()

# FastAPI app
app = FastAPI(title="GitLab Security Scanner")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Startup and shutdown
@app.on_event("startup")
async def startup():
    await db.init()
    await db.create_all()

@app.on_event("shutdown")
async def shutdown():
    await gitlab.close()
    await db.close()

# Routes
@app.get("/")
async def root():
    """API root with available endpoints"""
    return {
        "status": "running",
        "version": "1.0.0",
        "endpoints": [
            "/api/gitlab/login",
            "/api/gitlab/oauth/callback",
            "/api/gitlab/repos",
            "/api/gitlab/scan/{scan_id}/status",
            "/health"
        ]
    }

@app.get("/api/gitlab/login")
async def gitlab_login():
    """Start GitLab OAuth flow"""
    params = {
        'client_id': GITLAB_CLIENT_ID,
        'redirect_uri': GITLAB_REDIRECT_URI,
        'response_type': 'code',
        'scope': 'api read_user read_repository'
    }
    
    authorize_url = f"{GITLAB_URL}/oauth/authorize"
    query_string = "&".join(f"{k}={v}" for k, v in params.items())
    
    return RedirectResponse(f"{authorize_url}?{query_string}")

@app.get("/api/gitlab/oauth/callback")
async def gitlab_callback(
    code: str,
    background_tasks: BackgroundTasks
):
    """Handle GitLab OAuth callback"""
    try:
        # Exchange code for token
        async with aiohttp.ClientSession() as session:
            token_response = await session.post(
                f"{GITLAB_URL}/oauth/token",
                data={
                    'client_id': GITLAB_CLIENT_ID,
                    'client_secret': GITLAB_CLIENT_SECRET,
                    'code': code,
                    'grant_type': 'authorization_code',
                    'redirect_uri': GITLAB_REDIRECT_URI
                }
            )
            
            token_data = await token_response.json()
            if 'error' in token_data:
                raise HTTPException(status_code=400, detail=token_data['error'])
            
            access_token = token_data['access_token']
            
            # Get user info
            user = await gitlab.verify_token(access_token)
            
            # Connect account and start scans
            async with db._session.begin():
                # Get user's GitLab projects
                async with aiohttp.ClientSession() as session:
                    projects_response = await session.get(
                        f"{GITLAB_URL}/api/v4/projects?owned=true",
                        headers={"Authorization": f"Bearer {access_token}"}
                    )
                    projects = await projects_response.json()
                
                processed_repos = []
                for project in projects:
                    # Check if repository exists
                    stmt = select(UserRepository).where(
                        UserRepository.user_id == str(user.id),
                        UserRepository.gitlab_project_id == project['id']
                    )
                    result = await db._session.execute(stmt)
                    repo = result.scalar_one_or_none()
                    
                    if repo:
                        repo.repository_name = project['name']
                        repo.repository_url = project['web_url']
                    else:
                        repo = UserRepository(
                            user_id=str(user.id),
                            gitlab_project_id=project['id'],
                            repository_name=project['name'],
                            repository_url=project['web_url'],
                            default_branch=project['default_branch'],
                            visibility=project['visibility'],
                            size_mb=project.get('statistics', {}).get('repository_size', 0) / 1024 / 1024
                        )
                        db._session.add(repo)
                        await db._session.flush()
                    
                    scan = ScanResult(
                        repository_id=repo.id,
                        user_id=str(user.id),
                        status=ScanStatus.PENDING,
                        branch=project['default_branch'],
                        scan_date=datetime.utcnow()
                    )
                    db._session.add(scan)
                    await db._session.flush()
                    
                    processed_repos.append({
                        'id': repo.id,
                        'name': project['name'],
                        'url': project['web_url'],
                        'scan_id': scan.id
                    })
                    
                    # Schedule scan
                    background_tasks.add_task(
                        gitlab.scan_repository,
                        user_id=str(user.id),
                        repo_id=repo.id,
                        access_token=access_token,
                        gitlab_project_id=project['id'],
                        scan_id=scan.id
                    )
            
            return JSONResponse({
                'success': True,
                'message': f'Successfully connected GitLab account and initiated scans for {len(processed_repos)} repositories',
                'repositories': processed_repos,
                'user': {
                    'id': user.id,
                    'username': user.username
                }
            })
            
    except Exception as e:
        logger.error("oauth_callback_failed", error=str(e))
        raise HTTPException(status_code=500, detail="OAuth process failed")

@app.get("/api/gitlab/repos")
async def list_repos(request: Request):
    """List user's GitLab repositories and scan results"""
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        user = await gitlab.verify_token(token.split()[1])
        
        async with db._session() as session:
            # Get all active repositories for user
            stmt = select(UserRepository).where(
                UserRepository.user_id == str(user.id),
                UserRepository.is_active == True
            )
            result = await session.execute(stmt)
            repositories = result.scalars().all()
            
            results = []
            for repo in repositories:
                # Get latest scan for each repository
                stmt = select(ScanResult).where(
                    ScanResult.repository_id == repo.id
                ).order_by(ScanResult.scan_date.desc()).limit(1)
                scan_result = await session.execute(stmt)
                latest_scan = scan_result.scalar_one_or_none()
                
                if latest_scan:
                    result = {
                        'repository': {
                            'id': repo.id,
                            'name': repo.repository_name,
                            'url': repo.repository_url,
                            'last_scan': repo.last_scan_at.isoformat() if repo.last_scan_at else None
                        },
                        'scan_results': {
                            'status': latest_scan.status.value,
                            'scan_date': latest_scan.scan_date.isoformat(),
                        }
                    }
                    
                    if latest_scan.status == ScanStatus.COMPLETED:
                        result['scan_results'].update({
                            'findings_count': latest_scan.findings_count,
                            'severity_counts': {
                                'critical': latest_scan.critical_count,
                                'high': latest_scan.high_count,
                                'medium': latest_scan.medium_count,
                                'low': latest_scan.low_count
                            }
                        })
                    elif latest_scan.status == ScanStatus.FAILED:
                        result['scan_results']['error'] = latest_scan.error_message
                        
                    results.append(result)
            
            return {
                'success': True,
                'data': {
                    'user_id': str(user.id),
                    'repositories': results
                }
            }
            
    except Exception as e:
        logger.error("list_repos_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/gitlab/scan/{scan_id}/status", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: int, request: Request):
    """Get the status of a specific scan"""
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        user = await gitlab.verify_token(token.split()[1])
        
        async with db._session() as session:
            stmt = select(ScanResult).where(
                ScanResult.id == scan_id,
                ScanResult.user_id == str(user.id)
            )
            result = await session.execute(stmt)
            scan = result.scalar_one_or_none()
            
            if not scan:
                raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
            
            return {
                'scan_id': scan.id,
                'status': scan.status,
                'repository_id': scan.repository_id,
                'error': scan.error_message,
                'findings_count': scan.findings_count if scan.status == ScanStatus.COMPLETED else None
            }
            
    except Exception as e:
        logger.error("get_scan_status_failed", scan_id=scan_id, error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        # Verify database connection
        async with db._session() as session:
            await session.execute(select(1))
        
        # Verify semgrep installation
        process = await asyncio.create_subprocess_exec(
            'semgrep',
            '--version',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await process.communicate()
        
        return {
            'status': 'healthy',
            'database': 'connected',
            'semgrep_version': stdout.decode().strip()
        }
    except Exception as e:
        logger.error("health_check_failed", error=str(e))
        return JSONResponse(
            status_code=500,
            content={
                'status': 'unhealthy',
                'error': str(e)
            }
        )

# Signal handlers
async def shutdown_signal_handler():
    """Handle shutdown signals gracefully"""
    logger.info("shutting_down_application")
    
    # Cancel all running tasks
    for task in asyncio.all_tasks():
        if task is not asyncio.current_task():
            task.cancel()
    
    # Wait for tasks to complete
    await asyncio.gather(*asyncio.all_tasks(), return_exceptions=True)
    
    # Cleanup
    await gitlab.close()
    await db.close()

def handle_signals():
    loop = asyncio.get_event_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(
            sig,
            lambda s=sig: asyncio.create_task(shutdown_signal_handler())
        )

if __name__ == "__main__":
    handle_signals()
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        workers=4,
        loop="asyncio",
        log_level="info",
        access_log=True
    )