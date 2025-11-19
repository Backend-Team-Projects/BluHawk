import json
import logging
import threading
import uuid
from django.http import JsonResponse
from django.urls import resolve, Resolver404
from django.utils.timezone import now
from .models import OrganizationManagement, Scanlog
from attack_surface.models import Notification
from user_settings.models import UserProfile
from BluHawk.config import view_display_pairs, role_based_views, COMPLIANCE_RULES
from BluHawk.utils import *
import re

logger = logging.getLogger(__name__)


def auto_map_compliance(response_json):
    mapped = set()

    def match_value_regex(value):
        if not isinstance(value, str):
            return set()
        matched = set()
        for rule_key, standards in COMPLIANCE_RULES.items():
            if rule_key.startswith("regex:"):
                pattern = rule_key[len("regex:"):]
                if re.match(pattern, value):
                    matched.update(standards)
        return matched

    if isinstance(response_json, dict):
        for key, value in response_json.items():
            if key in COMPLIANCE_RULES:
                mapped.update(COMPLIANCE_RULES[key])

            if isinstance(value, dict):
                mapped.update(auto_map_compliance(value))
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        mapped.update(auto_map_compliance(item))
                    else:
                        mapped.update(match_value_regex(item))
            else:
                mapped.update(match_value_regex(value))

    elif isinstance(response_json, list):
        for item in response_json:
            if isinstance(item, dict):
                mapped.update(auto_map_compliance(item))
            else:
                mapped.update(match_value_regex(item))

    return list(mapped)


class OrganizationContextMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.view_display_names = view_display_pairs
        self.included_views = list(view_display_pairs.keys())

    def __call__(self, request):

        if not request.user.is_authenticated:
            return self.get_response(request)

        try:
            try:
                resolved = resolve(request.path_info)
                current_view = resolved.url_name
            except Resolver404:
                return self.get_response(request)

            if current_view not in self.included_views:
                return self.get_response(request)

            # ---------------------------------------------------
            # 1️⃣ CHECK USER ORGANIZATION MEMBERSHIP
            # ---------------------------------------------------
            memberships = OrganizationManagement.objects.filter(
                user=request.user
            ).select_related('organization')

            user_has_org = memberships.exists()

            # ---------------------------------------------------
            # CASE A: USER HAS **NO ORGANIZATION** → AUTO-VIEWER
            # ---------------------------------------------------
            if not user_has_org:
                logger.warning(f"User {request.user.email} has no organization memberships")

                active_org = None
                active_role = "viewer"

                # allow scan to proceed without org
                response = self.get_response(request)

                # log scan as viewer with no org
                self._log_scan(
                    request,
                    response,
                    current_view,
                    organization=None,
                    role="viewer"
                )

                return response

            # ---------------------------------------------------
            # CASE B: USER HAS ORGANIZATIONS → OLD LOGIC APPLIES
            # ---------------------------------------------------

            # collect orgs + roles
            request.user_organizations = [
                {
                    'id': str(m.organization.id).replace('-', ''),
                    'name': m.organization.name,
                    'role': m.role
                }
                for m in memberships
            ]

            request.user_org_roles = {
                str(m.organization.id).replace('-', ''): m.role
                for m in memberships
            }

            # ACTIVE ORG CHECK
            try:
                profile = UserProfile.objects.get(user=request.user)
                active_org = profile.active_organization
            except UserProfile.DoesNotExist:
                active_org = None

            if not active_org:
                return JsonResponse(
                    {'message': 'Please set an active organization before running this scan.'},
                    status=403
                )

            membership = OrganizationManagement.objects.filter(
                user=request.user, organization=active_org
            ).first()

            active_role = membership.role if membership else None

            # ROLE PERMISSION CHECK
            if not active_role or current_view not in role_based_views.get(active_role, []):
                return JsonResponse({'message': 'You are not allowed to access this scan.'}, status=403)

            # RUN VIEW
            response = self.get_response(request)

            # LOG FOR ORG USERS
            self._log_scan(
                request,
                response,
                current_view,
                organization=active_org,
                role=active_role
            )

            return response

        except Exception as e:
            log_exception(e)
            logger.error(f"Error in OrganizationContextMiddleware: {str(e)}", exc_info=True)
            return JsonResponse(
                {'message': 'An error occurred while processing organization context.'},
                status=500
            )

    # ---------------------------------------------------------
    # BACKGROUND LOGGING FUNCTION
    # ---------------------------------------------------------
    def _log_scan(self, request, response, current_view, organization, role):
        def log_thread():
            try:
                if response.status_code != 200:
                    return

                scan_name = self.view_display_names.get(current_view, current_view)

                # JSON parsing
                if hasattr(response, 'content') and response.get('Content-Type', '').startswith('application/json'):
                    try:
                        json_data = json.loads(response.content.decode('utf-8', errors='ignore'))
                    except json.JSONDecodeError:
                        json_data = {"error": "Failed to decode JSON response"}
                else:
                    json_data = {"note": "No JSON content in response"}

                compliance_mappings = auto_map_compliance(json_data)

                Notification.objects.create(
                    email=request.user.email,
                    heading=f"Scan Completed: {scan_name}",
                    message=f"Your scan '{scan_name}' was completed successfully.",
                    actionable=False,
                    json_data=json_data,
                    type='Scan Completed',
                    organization_id=str(organization.id).replace('-', '') if organization else None,
                )

                Scanlog.objects.create(
                    user=request.user,
                    scan_name=scan_name,
                    group='organization' if organization else 'none',
                    status_code=response.status_code,
                    organization=organization,
                    role=role,
                    timestamp=now(),
                    json_data=json_data,
                    compliance_mappings=compliance_mappings,
                )

            except Exception as e:
                logger.error(f"Failed to log Scanlog/Notification: {str(e)}", exc_info=True)

        threading.Thread(target=log_thread).start()
