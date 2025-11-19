import json
import logging
import threading
import re
from django.http import JsonResponse
from django.urls import resolve, Resolver404
from django.utils.timezone import now

from .models import OrganizationManagement, Scanlog
from attack_surface.models import Notification
from user_settings.models import UserProfile
from BluHawk.config import view_display_pairs, role_based_views, COMPLIANCE_RULES
from BluHawk.utils import *

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


# -----------------------------------------------------------
# SCAN ENDPOINTS LIST → Only these endpoints are restricted
# -----------------------------------------------------------
SCAN_ENDPOINTS = set(
    role_based_views["admin"]
    + role_based_views["analyst"]
    + role_based_views["viewer"]
)


class OrganizationContextMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.view_display_names = view_display_pairs  # Display names for logs
        self.loggable_views = list(view_display_pairs.keys())  # Logging only

    def __call__(self, request):
        
        if not request.user.is_authenticated:
            return self.get_response(request)
        
        try:
            # ---------------------------------------------
            # RESOLVE VIEW
            # ---------------------------------------------
            current_view = None   # prevent UnboundLocalError
            try:
                resolved = resolve(request.path_info)
                current_view = resolved.url_name
            except Resolver404:
                return self.get_response(request)
            print("=== MIDDLEWARE HIT ===", current_view)
            is_scan_endpoint = current_view in SCAN_ENDPOINTS

            # ---------------------------------------------
            # FETCH USER ORG MEMBERSHIP
            # ---------------------------------------------
            memberships = OrganizationManagement.objects.filter(
                user=request.user
            ).select_related("organization")

            user_has_org = memberships.exists()

            # =========================================================
            # CASE A: USER HAS NO ORGANIZATION → viewer
            # =========================================================
            if not user_has_org:
                active_role = "viewer"

                if is_scan_endpoint:
                    blocked_list = role_based_views["viewer"]

                    # REVERSED LOGIC → block if inside viewer list
                    if current_view in blocked_list:
                        return JsonResponse(
                            {"message": "Viewer role is not allowed for this scan."},
                            status=403
                        )

                response = self.get_response(request)

                # Log only if endpoint is listed in view_display_pairs
                if current_view in self.loggable_views and response.status_code == 200:
                    self._log_scan(request, response, current_view, None, "viewer")

                return response

            # =========================================================
            # CASE B: USER HAS ORGANIZATION
            # =========================================================
            try:
                profile = UserProfile.objects.get(user=request.user)
                active_org = profile.active_organization
            except UserProfile.DoesNotExist:
                active_org = None

            if not active_org:
                return JsonResponse(
                    {"message": "Please set an active organization before running this scan."},
                    status=403
                )

            membership = OrganizationManagement.objects.filter(
                user=request.user, organization=active_org
            ).first()

            active_role = membership.role if membership else "viewer"

            # ---------------------------------------------------------
            # REVERSED ROLE LOGIC ONLY FOR SCAN ENDPOINTS
            # ---------------------------------------------------------
            if is_scan_endpoint:
                blocked_list = role_based_views.get(active_role, [])

                if active_role != "admin" and current_view in blocked_list:
                    return JsonResponse(
                        {"message": "You are not allowed to access this scan."},
                        status=403
                    )

            # ALLOWED → RUN VIEW
            response = self.get_response(request)

            # LOGGING ONLY IF (in view_display_pairs + 200 OK)
            if current_view in self.loggable_views and response.status_code == 200:
                self._log_scan(request, response, current_view, active_org, active_role)

            return response

        except Exception as e:
            log_exception(e)
            logger.error(f"Error in OrganizationContextMiddleware: {str(e)}", exc_info=True)
            return JsonResponse({"message": "An internal error occurred."}, status=500)
    
    # ---------------------------------------------------------
    # BACKGROUND LOGGING FUNCTION
    # ---------------------------------------------------------
    def _log_scan(self, request, response, current_view, organization, role):
        def log_thread():
            try:
                if response.status_code != 200:
                    return

                scan_name = self.view_display_names.get(current_view, current_view)

                if hasattr(response, "content") and response.get("Content-Type", "").startswith("application/json"):
                    try:
                        json_data = json.loads(response.content.decode("utf-8", errors="ignore"))
                    except json.JSONDecodeError:
                        json_data = {"error": "Invalid JSON"}
                else:
                    json_data = {"note": "No JSON content"}

                compliance_mappings = auto_map_compliance(json_data)

                Notification.objects.create(
                    email=request.user.email,
                    heading=f"Scan Completed: {scan_name}",
                    message=f"Your scan '{scan_name}' finished successfully.",
                    actionable=False,
                    json_data=json_data,
                    type="Scan Completed",
                    organization_id=str(organization.id).replace("-", "") if organization else None,
                )

                Scanlog.objects.create(
                    user=request.user,
                    scan_name=scan_name,
                    group="organization" if organization else "none",
                    status_code=response.status_code,
                    organization=organization,
                    role=role,
                    timestamp=now(),
                    json_data=json_data,
                    compliance_mappings=compliance_mappings,
                )

            except Exception as e:
                logger.error(f"Logging failed: {str(e)}", exc_info=True)

        threading.Thread(target=log_thread).start()
