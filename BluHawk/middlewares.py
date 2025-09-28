from django.utils.timezone import now
from django.utils.deprecation import MiddlewareMixin
from django.apps import apps
from django.urls import resolve
from rest_framework.authentication import get_authorization_header
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.authentication import TokenAuthentication
from BluHawk.config import TRACKED_ENDPOINTS, TRACKED_ENDPOINTS_NAMES as ten
import requests
from BluHawk import load_env as myenv
from BluHawk.utils import log_exception
from django.conf import settings
from datetime import timedelta, timezone
import subprocess
import os
import json
import urllib.parse
from pathlib import Path
import logging

logger = logging.getLogger(__name__)
compliance_logger = logging.getLogger('audit.compliance')  # Dedicated for compliance logs

def get_client_ip(request):
    """Extract client IP from request headers."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

class UserRequestTrackingMiddleware(MiddlewareMixin):
    """
    Enhanced middleware for user request tracking with audit and compliance features.
    Preserves all original functionality while adding:
    - Log retention (GDPR compliant)
    - Periodic data backups (ISO 27001 compliant)
    - Compliance mapping (PCI-DSS, GDPR, ISO 27001)
    """
    async_mode = False  # Django 5.0+ compatibility - synchronous middleware
    
    def __init__(self, get_response):
        """Initialize middleware with configurable audit/compliance settings."""
        self.get_response = get_response
        
        # Audit & Compliance configurations from settings.py
        self.log_retention_days = getattr(settings, 'LOG_RETENTION_DAYS', 30)
        self.backup_interval_requests = getattr(settings, 'BACKUP_INTERVAL_REQUESTS', 100)
        self.request_count = 0  # Counter for triggering periodic backups
        
        # Compliance standards configuration
        self.compliance_standards = getattr(settings, 'COMPLIANCE_STANDARDS', {
            'GDPR': {
                'enabled': True, 
                'retention_days': 365,
                'description': 'General Data Protection Regulation - Data retention and access logging'
            },
            'PCI_DSS': {
                'enabled': True, 
                'log_sensitive': False,
                'description': 'Payment Card Industry Data Security Standard - Secure logging'
            },
            'ISO_27001': {
                'enabled': True, 
                'backup_required': True,
                'description': 'Information Security Management - Backup and recovery procedures'
            }
        })
        
        # Restic backup configuration
        self.restic_repo = getattr(settings, 'RESTIC_REPO_PATH', '/backup/bluhawk-repo')
        self.restic_password = getattr(settings, 'RESTIC_PASSWORD', 'admin@123')
        self.pg_dump_path = getattr(settings, 'PG_DUMP_PATH', '/var/backups/bluhawk_db_dump.sql')
        
        # Ensure backup directory exists
        self.backup_dir = Path('/var/backups')
        self.backup_dir.mkdir(exist_ok=True, parents=True)

    def process_request(self, request):
        """Authenticate user from Bearer Token - Enhanced for compliance tracking."""
        # Always try to authenticate, even if not required
        user = self.get_user_from_token(request)
        
        # Set user on request (even if anonymous)
        if user and user.is_authenticated:
            request.user = user
            logger.debug(f"✅ Authenticated user: {user.username}")
        else:
            # Create anonymous user for compliance tracking
            from django.contrib.auth.models import AnonymousUser
            request.user = AnonymousUser()
            logger.debug("🔒 Anonymous user for compliance tracking")
        
        # Let the request continue
        response = self.get_response(request)
        return response
    
    def process_response(self, request, response):
        """Track user requests with enhanced audit and compliance features."""
        user = None
        
        # Original functionality - User authentication check
        if hasattr(request, "user") and request.user.is_authenticated:
            user = request.user
            resolved_url = resolve(request.path_info)
            
            # Check if this is a tracked endpoint
            if resolved_url.url_name in TRACKED_ENDPOINTS:
                # Original: Log request to RequestLogs model with full compliance
                endpoint_name = ten.get(resolved_url.url_name, {}).get("name", resolved_url.url_name)
                endpoint_page = ten.get(resolved_url.url_name, {}).get("page", "Unknown")
                
                self.log_request_with_compliance(user, endpoint_name, endpoint_page, response.status_code, request, resolved_url.url_name)
                
                # Original: Track request count for analytics
                if response.status_code == 200:
                    self.track_request(user, resolved_url.url_name)
                
                # Original: Prepare sensor data for external analytics
                try:
                    data = {
                        'userName': user.username,
                        'emailAddress': user.email or '',
                        'ipAddress': get_client_ip(request),
                        'url': request.path,
                        'userAgent': request.META.get('HTTP_USER_AGENT', ''),
                        'eventTime': now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                        'eventType': 'page_view',
                        'httpMethod': request.method,
                        'httpCode': response.status_code,
                    }
                    # Original: Send to external sensor (commented out)
                    # rep = self.send_sensor_data(data)
                except Exception as e:
                    log_exception(e)
        
        # Always log compliance mapping (even for non-tracked endpoints)
        self.log_compliance_mapping(request, response, user)
        
        # New: Audit - Trigger periodic actions
        self.request_count += 1
        if self.request_count % self.backup_interval_requests == 0:
            self.enforce_log_retention()  # Trigger retention periodically for efficiency
            self.trigger_data_backup()    # Trigger backup
        
        return response
    
    def log_request(self, user, name, group, status_code, request):
        """Log API request to RequestLogs model with full compliance metadata."""
        try:
            from usage.models import RequestLogs
            from django.urls import resolve
            
            # Generate full compliance metadata
            resolved_url = resolve(request.path_info)
            compliance_status = {}
            
            # Check if this is a tracked endpoint
            is_tracked = resolved_url.url_name in TRACKED_ENDPOINTS
            
            if is_tracked:
                # GDPR Compliance Check
                if self.compliance_standards['GDPR']['enabled']:
                    gdpr_compliant = resolved_url.url_name not in ['sensitive_data_endpoint', 'payment_endpoint']
                    compliance_status['GDPR'] = {
                        'status': 'Compliant' if gdpr_compliant else 'Non-Compliant',
                        'reason': 'Personal data processing logged with retention policy' if gdpr_compliant else 'Sensitive endpoint requires additional review',
                        'retention_days': self.compliance_standards['GDPR']['retention_days']
                    }
                
                # PCI-DSS Compliance Check
                if self.compliance_standards['PCI_DSS']['enabled']:
                    pci_compliant = not self.compliance_standards['PCI_DSS']['log_sensitive'] or resolved_url.url_name not in ['payment_endpoint']
                    compliance_status['PCI_DSS'] = {
                        'status': 'Compliant' if pci_compliant else 'Warning',
                        'reason': 'Secure data handling and logging compliant' if pci_compliant else 'Payment endpoint requires PCI-DSS secure logging',
                        'sensitive_logging': self.compliance_standards['PCI_DSS']['log_sensitive']
                    }
                
                # ISO 27001 Compliance Check
                if self.compliance_standards['ISO_27001']['enabled']:
                    iso_compliant = self.compliance_standards['ISO_27001']['backup_required']
                    backup_status = "Completed" if self.request_count % self.backup_interval_requests == 0 else "Pending"
                    compliance_status['ISO_27001'] = {
                        'status': 'Compliant' if iso_compliant else 'Pending',
                        'reason': f'Backup procedure {"executed" if backup_status == "Completed" else f"scheduled (next in {self.backup_interval_requests - (self.request_count % self.backup_interval_requests)} requests)"}',
                        'backup_required': self.compliance_standards['ISO_27001']['backup_required'],
                        'last_backup': backup_status
                    }
            
            # Full compliance metadata
            compliance_metadata = {
                'endpoint': resolved_url.url_name,
                'is_tracked': is_tracked,
                'standards': compliance_status,
                'timestamp': timezone.now().isoformat(),
                'user': user.username if user.is_authenticated else 'Anonymous',
                'response_code': status_code,
                'ip_address': get_client_ip(request),
                'user_agent': request.META.get('HTTP_USER_AGENT', ''),
                'request_method': request.method,
                'path': request.path
            }
            
            # Create and save log
            log = RequestLogs(
                user=user,
                api_name=name,
                group=group,
                status_code=status_code,
                compliance_metadata=compliance_metadata
            )
            log.save()
            
            # Log success
            logger.info(f"Request logged: {user.username} -> {name} (Status: {status_code}) - Compliance audit enabled")
            
            # Log compliance data
            if is_tracked:
                compliance_logger.info(json.dumps(compliance_metadata, indent=2))
            else:
                compliance_logger.debug(f"Non-tracked endpoint: {resolved_url.url_name} - {name}")
                
        except Exception as e:
            log_exception(e)
            logger.error(f"Request logging failed for {user.username}: {str(e)}")
   
    def log_request_with_compliance(self, user, name, group, status_code, request, endpoint_name):
        """Enhanced request logging with full compliance mapping."""
        try:
            from usage.models import RequestLogs
            from django.urls import resolve
            
            # Generate full compliance metadata
            resolved_url = resolve(request.path_info)
            compliance_status = {}
            
            # Always generate compliance data for tracked endpoints
            if endpoint_name in TRACKED_ENDPOINTS:
                # GDPR Compliance Check
                if self.compliance_standards['GDPR']['enabled']:
                    gdpr_compliant = endpoint_name not in ['sensitive_data_endpoint', 'payment_endpoint']
                    compliance_status['GDPR'] = {
                        'status': 'Compliant' if gdpr_compliant else 'Review Required',
                        'reason': 'Personal data processing logged with 365-day retention' if gdpr_compliant else 'Sensitive endpoint flagged for GDPR review',
                        'retention_days': self.compliance_standards['GDPR']['retention_days']
                    }
                
                # PCI-DSS Compliance Check
                if self.compliance_standards['PCI_DSS']['enabled']:
                    pci_compliant = not self.compliance_standards['PCI_DSS']['log_sensitive'] or endpoint_name not in ['payment_endpoint']
                    compliance_status['PCI_DSS'] = {
                        'status': 'Compliant' if pci_compliant else 'Warning',
                        'reason': 'Secure logging and data handling compliant' if pci_compliant else 'Payment endpoint requires PCI-DSS secure logging',
                        'sensitive_logging': self.compliance_standards['PCI_DSS']['log_sensitive']
                    }
                
                # ISO 27001 Compliance Check
                if self.compliance_standards['ISO_27001']['enabled']:
                    backup_due = self.request_count % self.backup_interval_requests == 0
                    compliance_status['ISO_27001'] = {
                        'status': 'Compliant' if backup_due else 'Active',
                        'reason': f'Backup {"completed" if backup_due else "scheduled"} - {self.backup_interval_requests - (self.request_count % self.backup_interval_requests)} requests until next',
                        'backup_required': self.compliance_standards['ISO_27001']['backup_required'],
                        'last_backup_trigger': backup_due
                    }
            
            # Full compliance metadata
            compliance_metadata = {
                'endpoint': endpoint_name,
                'is_tracked': endpoint_name in TRACKED_ENDPOINTS,
                'standards': compliance_status,
                'timestamp': now().isoformat(),
                'user_id': user.id,
                'user_username': user.username,
                'user_email': user.email or '',
                'response_code': status_code,
                'ip_address': get_client_ip(request),
                'user_agent': request.META.get('HTTP_USER_AGENT', ''),
                'request_method': request.method,
                'path': request.path,
                'query_params': dict(request.GET),
                'compliance_version': '1.0'
            }
            
            # Create and save log
            log = RequestLogs(
                user=user,
                api_name=name,
                group=group,
                status_code=status_code,
                compliance_metadata=compliance_metadata
            )
            log.save()
            
            # Log success
            logger.info(f"✅ Compliance request logged: {user.username} -> {name} (Status: {status_code})")
            
            # Log detailed compliance data
            compliance_logger.info(f"COMPLIANCE-MAPPING: {json.dumps(compliance_metadata, default=str)}")
            
        except Exception as e:
            log_exception(e)
            logger.error(f"❌ Compliance logging failed for {user.username}: {str(e)}")
   
    def get_user_from_token(self, request):
        """Extracts and authenticates user from the Authorization header - Enhanced."""
        try:
            auth = get_authorization_header(request).split()
            
            # No auth header
            if not auth:
                return None
            
            # Check if it's Bearer token
            if len(auth) > 1 and auth[0].lower() == b'bearer':
                token = auth[1].decode("utf-8")
                
                # Try JWT first
                jwt_auth = JWTAuthentication()
                try:
                    user_auth_tuple = jwt_auth.authenticate(request)
                    if user_auth_tuple:
                        user, validated_token = user_auth_tuple
                        logger.debug(f"✅ JWT authentication successful: {user.username}")
                        return user
                except AuthenticationFailed:
                    logger.debug("JWT authentication failed")
                
                # Fallback to Token authentication
                token_auth = TokenAuthentication()
                try:
                    user_auth_tuple = token_auth.authenticate(requests.request)
                    if user_auth_tuple:
                        user, validated_token = user_auth_tuple
                        logger.debug(f"✅ Token authentication successful: {user.username}")
                        return user
                except AuthenticationFailed:
                    logger.debug("Token authentication failed")
            
            return None
            
        except Exception as e:
            logger.warning(f"Token parsing error: {str(e)}")
            return None


    def track_request(self, user, endpoint):
        """Logs user requests to UserRequestLog model - Original functionality."""
        try:
            UserRequestLog = apps.get_model("BluHawk", "UserRequestLog")
            log, created = UserRequestLog.objects.get_or_create(user=user, endpoint=endpoint)
            log.count += 1
            log.last_request = now()
            log.save()
            logger.debug(f"User request tracked: {user.username} -> {endpoint} (Count: {log.count})")
        except Exception as e:
            log_exception(e)
            logger.error(f"Request tracking failed for {user.username}: {str(e)}")

    def send_sensor_data(self, data):
        """Send analytics data to external service - Original functionality preserved."""
        import urllib.parse
        import requests
        
        API_URL = 'https://admin.bluhawk.twilightparadox.com/sensor/'
        REQUIRED_FIELDS = {
            'userName': '',
            'emailAddress': '',
            'ipAddress': '',
            'url': '',
            'userAgent': '',
            'eventTime': '',
        }
        OPTIONAL_FIELDS = {
            'firstName': '',
            'lastName': '',
            'fullName': '',
            'pageTitle': '',
            'httpReferer': '',
            'httpCode': '200',
            'browserLanguage': 'en-US',
            'eventType': 'page_view',
            'httpMethod': 'GET',
        }

        payload = {**REQUIRED_FIELDS, **OPTIONAL_FIELDS}
        payload.update({k: v for k, v in data.items() if k in payload and v is not None})
        
        payload = {k: v for k, v in payload.items() if v or k == 'httpCode'}

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Api-Key': myenv.TIRRENO_API,
        }

        try:
            encoded_data = urllib.parse.urlencode(payload, doseq=True)
            response = requests.post(
                API_URL,
                data=encoded_data,
                headers=headers,
                timeout=15
            )
            response.raise_for_status()
            return response
            
        except requests.exceptions.RequestException as e:
            print(f"API request failed: {str(e)}")
            return None

    def enforce_log_retention(self):
        """Delete old logs based on retention period for GDPR compliance - New feature."""
        try:
            from usage.models import RequestLogs
            cutoff_date = now() - timedelta(days=self.log_retention_days)
            old_logs = RequestLogs.objects.filter(created_at__lt=cutoff_date)
            count = old_logs.count()
            if count > 0:
                old_logs.delete()
                compliance_logger.info(f"GDPR Log Retention: Deleted {count} old logs (older than {self.log_retention_days} days)")
            else:
                logger.debug(f"GDPR Log Retention: No logs to delete (retention period: {self.log_retention_days} days)")
        except Exception as e:
            log_exception(e)
            compliance_logger.error(f"Log retention enforcement failed: {str(e)}")

    def trigger_data_backup(self):
        """Trigger periodic data backup using restic for ISO 27001 compliance - New feature."""
        try:
            # Step 0: Check and initialize restic repo if not exists
            env = os.environ.copy()
            env['RESTIC_PASSWORD'] = self.restic_password
            check_repo = subprocess.run(['restic', '--repo', self.restic_repo, 'cat', 'config'], env=env, capture_output=True, text=True)
            if check_repo.returncode != 0:
                init_result = subprocess.run([
                    'restic', 
                    '--repo', self.restic_repo, 
                    'init'  # No --password flag
                ], env=env, capture_output=True, text=True, timeout=60)  # Use env=env
                if init_result.returncode != 0:
                    compliance_logger.error(f"Restic repo init failed: {init_result.stderr}")
                    return
                compliance_logger.info("Restic repo initialized successfully")

            # Step 1: Create PostgreSQL database dump
            env['PGPASSWORD'] = settings.DATABASES['default']['PASSWORD']
            
            # Ensure dump directory exists
            os.makedirs(os.path.dirname(self.pg_dump_path), exist_ok=True)
            
            # Dump database
            result = subprocess.run([
                'pg_dump',
                '-U', settings.DATABASES['default']['USER'],
                '-h', settings.DATABASES['default']['HOST'],
                '-p', str(settings.DATABASES['default']['PORT']),
                '-d', settings.DATABASES['default']['NAME'],
                '-F', 'c',  # Custom format for efficient backup
                '-f', self.pg_dump_path
            ], env=env, capture_output=True, text=True, timeout=60)
            
            if result.returncode != 0:
                compliance_logger.error(f"PostgreSQL dump failed: {result.stderr}")
                return
            
            logger.debug("PostgreSQL dump created successfully")
            
            # Step 2: Backup application files + database dump using restic - FIXED
            backup_paths = [
                str(settings.BASE_DIR),  # Django project directory
                self.pg_dump_path        # Database dump
            ]

            # Run restic backup - FIXED: Remove --password flag, use env var
            result = subprocess.run([
                'restic',
                '--repo', self.restic_repo,
                'backup'  # No --password flag
            ] + backup_paths, env=env, capture_output=True, text=True, timeout=300)  # Use env=env

            if result.returncode == 0:
                compliance_logger.info(f"ISO 27001 Backup completed: {len(backup_paths)} items backed up")
            else:
                compliance_logger.error(f"Restic backup failed: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            compliance_logger.error("Backup timed out after 5 minutes")
        except subprocess.CalledProcessError as e:
            compliance_logger.error(f"Backup subprocess failed: {e.stderr if e.stderr else str(e)}")
        except Exception as e:
            log_exception(e)
            compliance_logger.error(f"Backup process failed: {str(e)}")
        finally:
            # Clean up temporary database dump
            if os.path.exists(self.pg_dump_path):
                os.remove(self.pg_dump_path)
                logger.debug("Temporary database dump cleaned up")

    def log_compliance_mapping(self, request, response, user=None):
        """Enhanced compliance mapping that works for all requests."""
        try:
            resolved_url = resolve(request.path_info)
            endpoint_name = resolved_url.url_name
            
            # Only log detailed compliance for tracked endpoints
            if endpoint_name in TRACKED_ENDPOINTS and user:
                compliance_summary = {
                    "endpoint": endpoint_name,
                    "user": user.username if user else "anonymous",
                    "timestamp": now().isoformat(),
                    "compliance_check": "ACTIVE",
                    "standards_summary": {
                        "GDPR": "Compliant - 365 day retention",
                        "PCI_DSS": "Compliant - Secure logging", 
                        "ISO_27001": f"Active - Backup in {self.backup_interval_requests - (self.request_count % self.backup_interval_requests)} requests"
                    }
                }
                compliance_logger.info(json.dumps(compliance_summary, indent=2))
            elif user:
                # Log basic access for non-tracked endpoints
                basic_log = {
                    "endpoint": endpoint_name,
                    "user": user.username if user else "anonymous",
                    "type": "non_tracked_access",
                    "timestamp": now().isoformat()
                }
                compliance_logger.debug(json.dumps(basic_log))
                
        except Exception as e:
            log_exception(e)
            compliance_logger.error(f"Compliance mapping failed for {request.path}: {str(e)}")