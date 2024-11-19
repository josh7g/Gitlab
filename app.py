from flask import Flask, request, redirect, jsonify, session
import os
from functools import wraps
import requests
from datetime import datetime
import logging
from sqlalchemy import create_engine, Column, Integer, String, DateTime, JSON, ForeignKey, Enum, Float, Text, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.dialects.postgresql import JSONB
import enum
import gitlab
from typing import Dict, Optional
import asyncio
import aiohttp  
from pathlib import Path
import tempfile
import shutil
import logging
import sys
import resource


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Initialize SQLAlchemy
Base = declarative_base()

class ScanStatus(enum.Enum):
    PENDING = "pending"
    SCANNING = "scanning"
    COMPLETED = "completed"
    FAILED = "failed"

# Database Models
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
    
    # Repository metadata
    default_branch = Column(String)
    visibility = Column(String)
    size_mb = Column(Float)
    
    # Relationships
    scan_results = relationship("ScanResult", back_populates="repository")

class ScanResult(Base):
    __tablename__ = 'scan_results'
    
    id = Column(Integer, primary_key=True)
    repository_id = Column(Integer, ForeignKey('user_repositories.id'))
    user_id = Column(String, nullable=False, index=True)
    scan_date = Column(DateTime, default=datetime.utcnow)
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING)
    
    # Scan metadata
    commit_sha = Column(String)
    branch = Column(String)
    
    # Results
    findings_count = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    
    # Full results stored as JSONB
    findings = Column(JSONB)
    error_message = Column(Text, nullable=True)
    
    # Performance metrics
    duration_seconds = Column(Float)
    files_scanned = Column(Integer)
    files_skipped = Column(Integer)
    
    # Relationship
    repository = relationship("UserRepository", back_populates="scan_results")

# GitLab Integration Class
class GitLabIntegration:
    def __init__(self, database_url: str, gitlab_url: str = "https://gitlab.com"):
        self.engine = create_engine(database_url)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self.gitlab_url = gitlab_url
    
    
    async def connect_gitlab_account(self, user_id: str, access_token: str) -> dict:
        """Connect user's GitLab account and trigger scans for their repositories"""
        session = self.Session()
        try:
            gl = gitlab.Gitlab(self.gitlab_url, oauth_token=access_token)
            gl.auth()
            
            projects = gl.projects.list(owned=True, all=True)
            processed_repos = []
            
            for project in projects:
                try:
                    # Check if repository exists
                    existing_repo = session.query(UserRepository).filter_by(
                        user_id=user_id,
                        gitlab_project_id=project.id
                    ).first()
                    
                    if existing_repo:
                        existing_repo.repository_name = project.name
                        existing_repo.repository_url = project.web_url
                        repo = existing_repo
                    else:
                        repo = UserRepository(
                            user_id=user_id,
                            gitlab_project_id=project.id,
                            repository_name=project.name,
                            repository_url=project.web_url,
                            default_branch=project.default_branch,
                            visibility=project.visibility,
                            size_mb=project.statistics()['repository_size'] / 1024 / 1024 if hasattr(project, 'statistics') else 0
                        )
                        session.add(repo)
                        session.flush()  # Flush to get the repo ID
                    
                    # Create and persist scan record before creating the task
                    scan = ScanResult(
                        repository_id=repo.id,
                        user_id=user_id,
                        status=ScanStatus.PENDING,
                        branch=project.default_branch,
                        scan_date=datetime.utcnow()
                    )
                    session.add(scan)
                    session.flush()  # Flush to get the scan ID
                    
                    processed_repos.append({
                        'id': repo.id,
                        'name': project.name,
                        'url': project.web_url,
                        'scan_id': scan.id  # Include scan ID in response
                    })
                    
                    logger.info(f"Created scan {scan.id} for repository {repo.id}")
                    
                    # Only create scan task if we have a valid scan ID
                    if scan.id:
                        asyncio.create_task(self._scan_repository(
                            user_id=user_id,
                            repo_id=repo.id,
                            access_token=access_token,
                            gitlab_project_id=project.id,
                            scan_id=scan.id
                        ))
                    else:
                        logger.error(f"Failed to get scan ID for repository {repo.id}")
                    
                except Exception as e:
                    logger.error(f"Error processing repository {project.name}: {str(e)}")
                    continue
            
            session.commit()
            return {
                'success': True,
                'message': f'Successfully connected GitLab account and initiated scans for {len(processed_repos)} repositories',
                'repositories': processed_repos
            }
            
        except Exception as e:
            logger.error(f"Error connecting GitLab account: {str(e)}")
            session.rollback()
            raise
        finally:
            session.close()
    
    async def get_user_scan_results(self, user_id: str) -> dict:
        """Get scan results for all user's repositories"""
        session = self.Session()
        try:
            repositories = session.query(UserRepository).filter_by(
                user_id=user_id,
                is_active=True
            ).all()
            
            results = []
            for repo in repositories:
                latest_scan = (
                    session.query(ScanResult)
                    .filter_by(repository_id=repo.id)
                    .order_by(ScanResult.scan_date.desc())
                    .first()
                )
                
                if latest_scan:
                    results.append({
                        'repository': {
                            'id': repo.id,
                            'name': repo.repository_name,
                            'url': repo.repository_url,
                            'last_scan': repo.last_scan_at.isoformat() if repo.last_scan_at else None
                        },
                        'scan_results': {
                            'status': latest_scan.status.value,
                            'scan_date': latest_scan.scan_date.isoformat(),
                            'findings_count': latest_scan.findings_count,
                            'severity_counts': {
                                'critical': latest_scan.critical_count,
                                'high': latest_scan.high_count,
                                'medium': latest_scan.medium_count,
                                'low': latest_scan.low_count
                            }
                        } if latest_scan.status == ScanStatus.COMPLETED else {
                            'status': latest_scan.status.value,
                            'error': latest_scan.error_message
                        }
                    })
            
            return {
                'success': True,
                'data': {
                    'user_id': user_id,
                    'repositories': results
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting scan results: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
        finally:
            session.close()

    @staticmethod
    async def verify_semgrep():
        """Verify semgrep is installed and working"""
        try:
            import subprocess
            result = subprocess.run(['semgrep', '--version'], 
                                    capture_output=True, 
                                    text=True)
            if result.returncode == 0:
                logger.info(f"Semgrep verified: {result.stdout.strip()}")
                return True
            else:
                logger.error(f"Semgrep check failed: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"Semgrep verification error: {str(e)}")
            return False



    async def _scan_repository(self, user_id: str, repo_id: int, access_token: str, 
                    gitlab_project_id: int, scan_id: int):
        """Run Semgrep scan on a repository and store results"""
        logger.info(f"Starting scan {scan_id} for repository {repo_id}")
        session = self.Session()
        temp_dir = None
        process = None
        
        try:
            if not await self.verify_semgrep():
                raise Exception("Semgrep is not properly installed")

            import resource
            resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, -1))

            scan = session.query(ScanResult).get(scan_id)
            if not scan:
                logger.error(f"Could not find scan with ID {scan_id}")
                return
            
            scan.status = ScanStatus.SCANNING
            session.commit()
            
            gl = gitlab.Gitlab(self.gitlab_url, oauth_token=access_token)
            project = gl.projects.get(gitlab_project_id)
                    
            temp_dir = Path(tempfile.mkdtemp(prefix='scanner_'))
            clone_url = project.http_url_to_repo.replace(
                "https://",
                f"https://oauth2:{access_token}@"
            )
            
            try:
                import git
                repo = git.Repo.clone_from(
                    clone_url,
                    temp_dir,
                    depth=1,
                    branch=project.default_branch,
                    single_branch=True,
                    filter=['blob:none'],
                    env={'GIT_HTTP_LOW_SPEED_LIMIT': '1000', 
                            'GIT_HTTP_LOW_SPEED_TIME': '10'}
                )
                
                cmd = [
                    "semgrep",
                    "scan",
                    "--config", "auto",
                    "--json",
                    "--quiet",
                    "--timeout", "10",
                    "--max-memory", "64",
                    "--jobs", "1", 
                    "--max-target-bytes", "100000",
                    "--max-files", "500",
                    "--timeout-threshold", "2",
                    str(temp_dir)
                ]
                
                start_time = datetime.now()
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                try:
                    stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30)
                    duration = (datetime.now() - start_time).total_seconds()
                    
                    if process.returncode == 0:
                        import json
                        results = json.loads(stdout)
                        findings = results.get('results', [])[:100]
                        
                        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
                        for finding in findings:
                            severity = finding.get('extra', {}).get('severity', 'LOW').upper()
                            severity_counts[severity] += 1
                        
                        session.refresh(scan)
                        scan.status = ScanStatus.COMPLETED
                        scan.findings = findings
                        scan.findings_count = len(findings)
                        scan.critical_count = severity_counts['CRITICAL']
                        scan.high_count = severity_counts['HIGH']
                        scan.medium_count = severity_counts['MEDIUM']
                        scan.low_count = severity_counts['LOW']
                        scan.duration_seconds = duration
                        scan.files_scanned = results.get('stats', {}).get('files_scanned', 0)
                        
                    else:
                        session.refresh(scan)
                        scan.status = ScanStatus.FAILED
                        scan.error_message = stderr.decode()
                        
                except asyncio.TimeoutError:
                    session.refresh(scan)
                    scan.status = ScanStatus.FAILED
                    scan.error_message = "Scan timeout exceeded"
                    
            except Exception as e:
                session.refresh(scan)
                scan.status = ScanStatus.FAILED
                scan.error_message = str(e)
                logger.error(f"Error during repository scan: {str(e)}")
            
            repo = session.query(UserRepository).get(repo_id)
            if repo:
                repo.last_scan_at = datetime.utcnow()
            
            session.commit()
            
        except Exception as e:
            logger.error(f"Error scanning repository {repo_id}: {str(e)}")
            try:
                scan = session.query(ScanResult).get(scan_id)
                if scan:
                    scan.status = ScanStatus.FAILED
                    scan.error_message = str(e)
                    session.commit()
            except Exception as inner_e:
                logger.error(f"Failed to update scan status: {str(inner_e)}")
                
        finally:
            if process:
                try:
                    process.kill()
                except:
                    pass
                    
            if temp_dir and temp_dir.exists():
                try:
                    shutil.rmtree(temp_dir)
                except Exception as e:
                    logger.error(f"Failed to cleanup temp directory: {str(e)}")
                    
            session.close()
    
    async def get_scan_status(self, scan_id: int) -> dict:
        """Get the current status of a scan"""
        session = self.Session()
        try:
            scan = session.query(ScanResult).get(scan_id)
            if not scan:
                return {'error': f'Scan {scan_id} not found'}
            
            return {
                'scan_id': scan.id,
                'status': scan.status.value,
                'repository_id': scan.repository_id,
                'error': scan.error_message if scan.error_message else None,
                'findings_count': scan.findings_count if scan.status == ScanStatus.COMPLETED else None,
            }
        finally:
            session.close()

# Flask Application
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')

# GitLab OAuth settings
GITLAB_CLIENT_ID = os.getenv('GITLAB_CLIENT_ID')
GITLAB_CLIENT_SECRET = os.getenv('GITLAB_CLIENT_SECRET')
GITLAB_REDIRECT_URI = os.getenv('GITLAB_REDIRECT_URI')
GITLAB_URL = 'https://gitlab.com'

# Initialize GitLab integration
gitlab_integration = GitLabIntegration(
    database_url=os.getenv('DATABASE_URL'),
    gitlab_url=GITLAB_URL
)

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'gitlab_token' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/api/gitlab/login')
def gitlab_login():
    """Start GitLab OAuth flow"""
    authorize_url = f"{GITLAB_URL}/oauth/authorize"
    params = {
        'client_id': GITLAB_CLIENT_ID,
        'redirect_uri': GITLAB_REDIRECT_URI,
        'response_type': 'code',
        'scope': 'api read_user read_repository'
    }
    
    return redirect(f"{authorize_url}?{'&'.join(f'{k}={v}' for k, v in params.items())}")

@app.route('/api/gitlab/oauth/callback')
async def gitlab_callback():
    """Handle GitLab OAuth callback"""
    if 'error' in request.args:
        return jsonify({'error': request.args['error']}), 400
    
    if 'code' not in request.args:
        return jsonify({'error': 'No code provided'}), 400
    
    # Exchange code for access token
    token_url = f"{GITLAB_URL}/oauth/token"
    data = {
        'client_id': GITLAB_CLIENT_ID,
        'client_secret': GITLAB_CLIENT_SECRET,
        'code': request.args['code'],
        'grant_type': 'authorization_code',
        'redirect_uri': GITLAB_REDIRECT_URI
    }
    
    try:
        async with aiohttp.ClientSession() as client_session:
            async with client_session.post(token_url, data=data) as response:
                token_data = await response.json()
                
                if 'error' in token_data:
                    logger.error(f"GitLab OAuth error: {token_data['error']}")
                    return jsonify({'error': token_data['error']}), 400
                
                if 'access_token' not in token_data:
                    logger.error(f"No access token in response: {token_data}")
                    return jsonify({'error': 'No access token received'}), 400
                
                # Get user info
                headers = {'Authorization': f"Bearer {token_data['access_token']}"}
                async with client_session.get(f"{GITLAB_URL}/api/v4/user", headers=headers) as user_response:
                    user_data = await user_response.json()
                    
                    if 'id' not in user_data:
                        logger.error(f"Invalid user data response: {user_data}")
                        return jsonify({'error': 'Failed to get user info'}), 400
                    
                    # Store in flask session
                    session['gitlab_token'] = token_data['access_token']
                    session['gitlab_user_id'] = user_data['id']
                    
                    try:
                        # Start scanning repositories
                        scan_result = await gitlab_integration.connect_gitlab_account(
                            user_id=str(user_data['id']),
                            access_token=token_data['access_token']
                        )
                        
                        return jsonify({
                            'success': True,
                            'message': 'Successfully connected GitLab account',
                            'scan_initiated': scan_result
                        })
                    except Exception as e:
                        logger.error(f"Repository scan error: {str(e)}")
                        return jsonify({
                            'success': False,
                            'error': 'Connected to GitLab but failed to scan repositories'
                        }), 500
                    
    except Exception as e:
        logger.error(f"OAuth error: {str(e)}")
        return jsonify({'error': 'OAuth process failed'}), 500
    
@app.route('/api/gitlab/repos')
@requires_auth
async def list_repos():
    """List user's GitLab repositories and scan results"""
    results = await gitlab_integration.get_user_scan_results(
        user_id=str(session['gitlab_user_id'])
    )
    return jsonify(results)

@app.route('/api/gitlab/scan/<int:scan_id>/status')
@requires_auth
async def get_scan_status(scan_id):
    """Get the status of a specific scan"""
    try:
        status = await gitlab_integration.get_scan_status(scan_id)
        return jsonify(status)
    except Exception as e:
        logger.error(f"Error getting scan status: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/health')
def health_check():
    """Health check endpoint that also verifies semgrep installation"""
    try:
        # Check if semgrep is installed and accessible
        import subprocess
        result = subprocess.run(['semgrep', '--version'], 
                              capture_output=True, 
                              text=True)
        semgrep_version = result.stdout.strip()
        
        return jsonify({
            'status': 'healthy',
            'semgrep_version': semgrep_version
        })
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 500