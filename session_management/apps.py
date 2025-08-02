
from django.apps import AppConfig

class SessionManagementConfig(AppConfig):
    name = 'session_management'

    def ready(self):
        import session_management.signals
