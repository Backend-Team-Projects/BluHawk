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

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


class UserRequestTrackingMiddleware(MiddlewareMixin):
    def process_request(self, request):
        """Authenticate user from Bearer Token."""
        user = self.get_user_from_token(request)
        if user and user.is_authenticated:
            request.user = user

    def process_response(self, request, response):
        """Track user request only if response status is 200."""
        if hasattr(request, "user") and request.user.is_authenticated:
            resolved_url = resolve(request.path_info)
            if resolved_url.url_name in TRACKED_ENDPOINTS:
                self.log_request(request.user, ten.get(resolved_url.url_name, {}).get("name", ""), ten.get(resolved_url.url_name, {}).get("page", ""), response.status_code)
                if response.status_code == 200:
                    pass
                    self.track_request(request.user, resolved_url.url_name)
            
            try:
                    user = request.user
                    data = {
                        'userName': user.username,
                        'emailAddress': user.email,
                        'ipAddress': get_client_ip(request),
                        'url': request.path,
                        'userAgent': request.META.get('HTTP_USER_AGENT', ''),
                        'eventTime': now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                        'eventType': 'page_view',
                        'httpMethod': request.method,
                        'httpCode': response.status_code,
                    }
                    # rep = self.send_sensor_data(data)

            except Exception as e:
                    log_exception(e)
        

        return response
    
    def log_request(self,user, name, group, status_code):
        from usage.models import RequestLogs
        log = RequestLogs(
            user=user,
            api_name=name,
            group=group,
            status_code=status_code
        )
        log.save()

    def get_user_from_token(self, request):
        """Extracts and authenticates user from the Authorization header."""
        auth = get_authorization_header(request).split()

        if not auth or auth[0].lower() != b"bearer":
            return None

        token = auth[1].decode("utf-8") if len(auth) > 1 else None
        if not token:
            return None

        for auth_class in [JWTAuthentication(), TokenAuthentication()]:
            try:
                user_auth_tuple = auth_class.authenticate(request)
                if user_auth_tuple:
                    return user_auth_tuple[0]
            except AuthenticationFailed:
                continue

        return None

    def track_request(self, user, endpoint):
        """Logs user requests to the database."""
        UserRequestLog = apps.get_model("BluHawk", "UserRequestLog")
        
        log, created = UserRequestLog.objects.get_or_create(user=user, endpoint=endpoint)
        log.count += 1
        log.last_request = now()
        log.save()

    def send_sensor_data(self, data):

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
            'Api-Key': myenv.TIRRENO_API,  # Ensure this is properly configured
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
