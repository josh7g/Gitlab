from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Request,Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Enum, Float, Text, Boolean, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
from datetime import datetime
import json
import resource
import tempfile
import signal
import enum
import logging
import structlog
import os
from typing import Optional, List, Dict, Any
from pydantic import BaseModel
import git
import asyncio
import aiohttp
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
import fnmatch
import shutil
import psutil
from pathlib import Path


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = structlog.get_logger()

# Initialize FastAPI app
app = FastAPI(title="GitLab Security Scanner")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Constants
GITLAB_URL = os.getenv('GITLAB_URL', 'https://gitlab.com')
GITLAB_CLIENT_ID = os.getenv('GITLAB_CLIENT_ID')
GITLAB_CLIENT_SECRET = os.getenv('GITLAB_CLIENT_SECRET')
GITLAB_REDIRECT_URI = os.getenv('GITLAB_REDIRECT_URI')
DATABASE_URL = os.getenv('DATABASE_URL')

# Convert SQLAlchemy URL to async
ASYNC_DATABASE_URL = DATABASE_URL.replace('postgresql://', 'postgresql+asyncpg://')

# Scanner Configuration
@dataclass
class GitLabScanConfig:
    """Configuration for GitLab repository scanning"""
    max_file_size_mb: int = 25
    max_total_size_mb: int = 300
    max_memory_mb: int = 1500
    chunk_size_mb: int = 30
    max_files_per_chunk: int = 50
    
    timeout_seconds: int = 540  # 9 minutes
    chunk_timeout: int = 120    # 2 minutes per chunk
    file_timeout_seconds: int = 20
    max_retries: int = 2
    concurrent_processes: int = 1

    exclude_patterns: List[str] = field(default_factory=lambda: [
        '.git', '.svn', 'node_modules', 'vendor',
        'bower_components', 'packages', 'dist',
        'build', 'out', 'venv', '.env', '__pycache__',
        '*.min.*', '*.bundle.*', '*.map', 
        '*.{pdf,jpg,jpeg,png,gif,zip,tar,gz,rar,mp4,mov}',
        'package-lock.json', 'yarn.lock',
        'coverage', 'test*', 'docs'
    ])

# Database Models
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

# Pydantic Models
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

# Database Session
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

# Security Scanner Implementation
class GitLabSecurityScanner:
    """Enhanced security scanner for GitLab repositories"""
    
    def __init__(self, config: GitLabScanConfig = GitLabScanConfig()):
        self.config = config
        self.temp_dir = None
        self.repo_dir = None
        self.scan_stats = {
            'start_time': None,
            'end_time': None,
            'total_files': 0,
            'files_processed': 0,
            'files_skipped': 0,
            'files_too_large': 0,
            'total_size_mb': 0,
            'memory_usage_mb': 0,
            'findings_count': 0
        }

    async def __aenter__(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix='gitlab_scanner_'))
        logger.info(f"Created temporary directory: {self.temp_dir}")
        self.scan_stats['start_time'] = datetime.now()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        try:
            if self.temp_dir and self.temp_dir.exists():
                shutil.rmtree(self.temp_dir)
                logger.info(f"Cleaned up temporary directory: {self.temp_dir}")
                self.scan_stats['end_time'] = datetime.now()
        except Exception as e:
            logger.error(f"Error during cleanup: {str(e)}")

    async def _clone_repository(self, clone_url: str, access_token: str, default_branch: str) -> Path:
        try:
            self.repo_dir = self.temp_dir / f"repo_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            auth_url = clone_url.replace('https://', f'https://oauth2:{access_token}@')
            
            logger.info(f"Cloning repository to {self.repo_dir}")
            
            git_options = [
                '--depth=1',
                '--single-branch',
                '--no-tags',
                f'--branch={default_branch}',
                '--filter=blob:none'
            ]
            
            repo = git.Repo.clone_from(
                auth_url,
                self.repo_dir,
                multi_options=git_options,
                env={
                    'GIT_HTTP_LOW_SPEED_LIMIT': '1000',
                    'GIT_HTTP_LOW_SPEED_TIME': '10',
                    'GIT_ALLOC_LIMIT': '256M',
                    'GIT_PACK_THREADS': '1'
                }
            )

            return self.repo_dir

        except Exception as e:
            if self.repo_dir and self.repo_dir.exists():
                shutil.rmtree(self.repo_dir)
            raise RuntimeError(f"Repository clone failed: {str(e)}") from e

    async def _scan_chunk(self, files: List[str]) -> List[Dict]:
        """Scan a single chunk of files using Semgrep registry rules"""
        try:
            cmd = [
                "semgrep",
                "scan",
                "--json",
                "--config", "p/ci",  # Use the CI ruleset from registry
                "--metrics=off",  # Explicitly disable metrics
                f"--max-memory={self.config.max_memory_mb}",
                "--optimizations=all",
                "--timeout", str(self.config.file_timeout_seconds),   
            ] + files

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                limit=1024 * 1024 * 10  # 10MB buffer for output
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.config.chunk_timeout
                )
            except asyncio.TimeoutError:
                if process.returncode is None:
                    process.terminate()
                    await process.wait()
                logger.warning(f"Scan timeout for chunk with {len(files)} files")
                return []

            # Handle semgrep output
            stdout_output = stdout.decode() if stdout else ""
            stderr_output = stderr.decode() if stderr else ""

            # Log errors that aren't just informational
            if stderr_output and not any(x in stderr_output for x in ['METRICS:', 'Running autofix']):
                logger.warning(f"Semgrep stderr: {stderr_output}")

            if process.returncode not in [0, 1]:
                logger.error(f"Semgrep exited with code {process.returncode}")
                if stderr_output:
                    logger.error(f"Error details: {stderr_output}")
                return []

            if not stdout_output.strip():
                return []

            try:
                results = json.loads(stdout_output)
                findings = results.get('results', [])
                
                # Enhanced logging
                if findings:
                    severities = {}
                    for finding in findings:
                        sev = finding.get('extra', {}).get('severity', 'unknown')
                        severities[sev] = severities.get(sev, 0) + 1
                    
                    logger.info(
                        f"Scan completed: {len(findings)} findings "
                        f"({', '.join(f'{k}: {v}' for k, v in severities.items())})"
                    )
                else:
                    logger.info("Scan completed: No findings")
                
                return findings

            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse Semgrep output: {str(e)}")
                return []

        except Exception as e:
            logger.error(f"Error during chunk scan: {str(e)}")
            return []

    def _process_results(self, findings: List[Dict]) -> Dict:
        """Process and categorize scan findings with enhanced metadata"""
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        category_counts = {}
        processed_findings = []
        files_with_findings = set()

        for finding in findings:
            severity = finding.get('extra', {}).get('severity', 'LOW').upper()
            category = finding.get('extra', {}).get('metadata', {}).get('category', 'security')
            file_path = finding.get('path', '')
            
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            category_counts[category] = category_counts.get(category, 0) + 1
            
            if file_path:
                files_with_findings.add(file_path)
            
            processed_findings.append({
                'id': finding.get('check_id'),
                'file': file_path,
                'line_start': finding.get('start', {}).get('line'),
                'line_end': finding.get('end', {}).get('line'),
                'code_snippet': finding.get('extra', {}).get('lines', ''),
                'message': finding.get('extra', {}).get('message', ''),
                'severity': severity,
                'category': category,
                'cwe': finding.get('extra', {}).get('metadata', {}).get('cwe', []),
                'owasp': finding.get('extra', {}).get('metadata', {}).get('owasp', []),
                'references': finding.get('extra', {}).get('metadata', {}).get('references', []),
                'fix_recommendations': finding.get('extra', {}).get('metadata', {}).get('fix', '')
            })

        self.scan_stats.update({
            'findings_count': len(findings),
            'files_with_findings': len(files_with_findings),
            'memory_usage_mb': psutil.Process().memory_info().rss / (1024 * 1024)
        })

        return {
            'findings': processed_findings[:100],  # Limit to 100 findings as before
            'stats': {
                'total_findings': len(findings),
                'severity_counts': severity_counts,
                'category_counts': category_counts,
                'scan_stats': self.scan_stats
            }
        }

    async def _run_chunked_scan(self, target_dir: Path) -> Dict:
        all_files = []
        chunks = []
        current_chunk = []
        
        for root, _, files in os.walk(target_dir):
            for file in files:
                if any(fnmatch.fnmatch(file, pattern) for pattern in self.config.exclude_patterns):
                    self.scan_stats['files_skipped'] += 1
                    continue
                
                file_path = Path(root) / file
                try:
                    size = file_path.stat().st_size / (1024 * 1024)  # MB
                    if size <= self.config.max_file_size_mb:
                        all_files.append((str(file_path), size))
                        self.scan_stats['total_size_mb'] += size
                    else:
                        self.scan_stats['files_too_large'] += 1
                except Exception as e:
                    logger.warning(f"Error accessing {file_path}: {e}")
        
        all_files.sort(key=lambda x: x[1], reverse=True)
        
        for file_path, size in all_files:
            if (len(current_chunk) >= self.config.max_files_per_chunk or 
                sum(s for _, s in current_chunk) + size > self.config.chunk_size_mb):
                if current_chunk:
                    chunks.append([f for f, _ in current_chunk])
                    current_chunk = []
            current_chunk.append((file_path, size))
        
        if current_chunk:
            chunks.append([f for f, _ in current_chunk])
        
        all_findings = []
        self.scan_stats['total_files'] = len(all_files)
        
        for i, chunk in enumerate(chunks, 1):
            logger.info(f"Processing chunk {i}/{len(chunks)} ({len(chunk)} files)")
            findings = await self._scan_chunk(chunk)
            all_findings.extend(findings)
            self.scan_stats['files_processed'] += len(chunk)

        return self._process_results(all_findings)

    def _process_results(self, findings: List[Dict]) -> Dict:
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        processed_findings = []

        for finding in findings:
            severity = finding.get('extra', {}).get('severity', 'LOW').upper()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            processed_findings.append({
                'id': finding.get('check_id'),
                'file': finding.get('path', ''),
                'line_start': finding.get('start', {}).get('line'),
                'line_end': finding.get('end', {}).get('line'),
                'code_snippet': finding.get('extra', {}).get('lines', ''),
                'message': finding.get('extra', {}).get('message', ''),
                'severity': severity,
                'category': finding.get('extra', {}).get('metadata', {}).get('category', 'security'),
                'cwe': finding.get('extra', {}).get('metadata', {}).get('cwe', []),
                'owasp': finding.get('extra', {}).get('metadata', {}).get('owasp', [])
            })

        self.scan_stats['findings_count'] = len(findings)
        self.scan_stats['memory_usage_mb'] = psutil.Process().memory_info().rss / (1024 * 1024)

        return {
            'findings': processed_findings[:100],  # Limit to 100 findings
            'stats': {
                'total_findings': len(findings),
                'severity_counts': severity_counts,
                'scan_stats': self.scan_stats
            }
        }

    async def scan_repository(self, clone_url: str, access_token: str, default_branch: str) -> Dict:
        try:
            repo_dir = await self._clone_repository(clone_url, access_token, default_branch)
            results = await self._run_chunked_scan(repo_dir)
            
            return {
                'success': True,
                'data': results,
                'metadata': {
                    'scan_duration': (datetime.now() - self.scan_stats['start_time']).total_seconds(),
                    'memory_usage_mb': self.scan_stats['memory_usage_mb']
                }}
            
        except Exception as e:
            logger.error(f"Scan failed: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }

# GitLab Integration
class GitLabIntegration:
    def __init__(self):
        self.scan_semaphore = asyncio.Semaphore(2)
        self.executor = ThreadPoolExecutor(max_workers=4)
        self._session = None
    
    async def init(self):
        if self._session is None:
            self._session = aiohttp.ClientSession()

    async def verify_token(self, access_token: str) -> UserData:
        if not self._session:
            await self.init()
            
        try:
            async with self._session.get(
                f"{GITLAB_URL}/api/v4/user",
                headers={"Authorization": f"Bearer {access_token}"}
            ) as response:
                if response.status != 200:
                    raise HTTPException(
                        status_code=401,
                        detail="Invalid or expired token"
                    )
                
                user_data = await response.json()
                return UserData(
                    id=user_data['id'],
                    username=user_data['username'],
                    email=user_data.get('email')
                )
        except Exception as e:
            logger.error("token_verification_failed", error=str(e))
            raise HTTPException(
                status_code=401,
                detail="Token verification failed"
            )

    async def close(self):
        if self._session:
            await self._session.close()
        self.executor.shutdown(wait=True)

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
                async with db._session.begin():
                    scan = await db._session.get(ScanResult, scan_id)
                    if not scan:
                        return
                    scan.status = ScanStatus.SCANNING
                
                # Get repository info from GitLab
                async with self._session.get(
                    f"{GITLAB_URL}/api/v4/projects/{gitlab_project_id}",
                    headers={"Authorization": f"Bearer {access_token}"}
                ) as response:
                    if response.status != 200:
                        raise Exception("Failed to get repository info")
                    project_data = await response.json()

                # Initialize scanner with configuration
                config = GitLabScanConfig()
                async with GitLabSecurityScanner(config) as scanner:
                    results = await scanner.scan_repository(
                        project_data['http_url_to_repo'],
                        access_token,
                        project_data['default_branch']
                    )

                    async with db._session.begin():
                        scan = await db._session.get(ScanResult, scan_id)
                        if results['success']:
                            findings = results['data']['findings']
                            stats = results['data']['stats']
                            
                            scan.status = ScanStatus.COMPLETED
                            scan.findings = findings
                            scan.findings_count = len(findings)
                            scan.critical_count = stats['severity_counts']['CRITICAL']
                            scan.high_count = stats['severity_counts']['HIGH']
                            scan.medium_count = stats['severity_counts']['MEDIUM']
                            scan.low_count = stats['severity_counts']['LOW']
                            scan.files_scanned = stats['scan_stats']['files_processed']
                            scan.files_skipped = stats['scan_stats']['files_skipped']
                            scan.duration_seconds = results['metadata']['scan_duration']
                        else:
                            scan.status = ScanStatus.FAILED
                            scan.error_message = str(results.get('error', 'Unknown error'))
                        
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

# Event Handlers
@app.on_event("startup")
async def startup():
    await db.init()
    await db.create_all()
    await gitlab.init()

@app.on_event("shutdown")
async def shutdown():
    await gitlab.close()
    await db.close()

# Routes
@app.get("/")
async def root():
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
async def gitlab_login(user_id: str):  # Simplified parameter
    """Start GitLab OAuth flow using provided user ID"""
    params = {
        'client_id': GITLAB_CLIENT_ID,
        'redirect_uri': GITLAB_REDIRECT_URI,
        'response_type': 'code',
        'scope': 'api read_user read_repository',
        'state': user_id  # Simply pass the user_id as state
    }
    
    authorize_url = f"{GITLAB_URL}/oauth/authorize"
    query_string = "&".join(f"{k}={v}" for k, v in params.items())
    
    return RedirectResponse(f"{authorize_url}?{query_string}")


@app.get("/api/gitlab/oauth/callback")
async def gitlab_callback(
    code: str,
    state: str,
    background_tasks: BackgroundTasks
):
    """Handle GitLab OAuth callback"""
    try:
        user_id = state  # Get the user_id directly from state
        
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
            gitlab_user = await gitlab.verify_token(access_token)
            
            # Rest of your existing code using the provided user_id
            async with db._session.begin():
                async with aiohttp.ClientSession() as session:
                    projects_response = await session.get(
                        f"{GITLAB_URL}/api/v4/projects?owned=true",
                        headers={"Authorization": f"Bearer {access_token}"}
                    )
                    projects = await projects_response.json()
                
                processed_repos = []
                for project in projects:
                    stmt = select(UserRepository).where(
                        UserRepository.user_id == user_id,
                        UserRepository.gitlab_project_id == project['id']
                    )
                    result = await db._session.execute(stmt)
                    repo = result.scalar_one_or_none()
                    
                    if repo:
                        repo.repository_name = project['name']
                        repo.repository_url = project['web_url']
                    else:
                        repo = UserRepository(
                            user_id=user_id,  
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
                        user_id=user_id,  
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
                    
                    background_tasks.add_task(
                        gitlab.scan_repository,
                        user_id=user_id,
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
                    'id': user_id,
                    'gitlab_username': gitlab_user.username
                }
            })
            
    except Exception as e:
        logger.error("oauth_callback_failed", error=str(e))
        raise HTTPException(status_code=500, detail="OAuth process failed")

@app.get("/api/gitlab/repos")
async def list_repos(request: Request):
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        user = await gitlab.verify_token(token.split()[1])
        
        async with db._session() as session:
            stmt = select(UserRepository).where(
                UserRepository.user_id == str(user.id),
                UserRepository.is_active == True
            )
            result = await session.execute(stmt)
            repositories = result.scalars().all()
            
            results = []
            for repo in repositories:
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
    try:
        async with db._session() as session:
            await session.execute(select(1))
        
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
    logger.info("initiating_graceful_shutdown")
    
    running_tasks = [
        task for task in asyncio.all_tasks()
        if task is not asyncio.current_task() 
        and not task.done()
        and 'scan_repository' in str(task.get_coro())
    ]
    
    if running_tasks:
        logger.info(f"waiting_for_{len(running_tasks)}_scans_to_complete")
        
        try:
            await asyncio.wait_for(
                asyncio.gather(*running_tasks, return_exceptions=True),
                timeout=300
            )
        except asyncio.TimeoutError:
            logger.warning("some_scans_did_not_complete_in_time")
            for task in running_tasks:
                if not task.done():
                    task.cancel()
    
    other_tasks = [
        task for task in asyncio.all_tasks()
        if task is not asyncio.current_task() 
        and not task.done()
        and 'scan_repository' not in str(task.get.get_coro())
    ]
    
    for task in other_tasks:
        task.cancel()
    
    if other_tasks:
        await asyncio.gather(*other_tasks, return_exceptions=True)
    
    # Cleanup
    await gitlab.close()
    await db.close()
    
    logger.info("shutdown_complete")

def handle_signals():
    """Configure signal handlers for graceful shutdown"""
    loop = asyncio.get_event_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(
            sig,
            lambda s=sig: asyncio.create_task(shutdown_signal_handler())
        )

# Error Handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "error": {
                "code": exc.status_code,
                "message": exc.detail
            }
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "error": {
                "code": 500,
                "message": "Internal server error",
                "detail": str(exc)
            }
        }
    )

# Main entry point
if __name__ == "__main__":
    import uvicorn
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Setup signal handlers
    handle_signals()
    
    # Run the application
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        workers=4,
        loop="asyncio",
        log_level="info",
        access_log=True,
        timeout_keep_alive=65,
        proxy_headers=True
    )