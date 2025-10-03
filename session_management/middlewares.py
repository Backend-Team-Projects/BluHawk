import json
import logging
import threading
import uuid
from django.http import JsonResponse
from django.urls import resolve, Resolver404
from django.utils.timezone import now
from .models import OrganizationManagement, Scanlog, Organization
from attack_surface.models import Notification
from user_settings.models import UserProfile
from BluHawk.config import view_display_pairs, role_based_views, COMPLIANCE_RULES  # ✅ import compliance rules
from BluHawk.utils import *

logger = logging.getLogger(__name__)


def auto_map_compliance(response_json):
    """Automatically map JSON keys to compliance standards from COMPLIANCE_RULES."""
    mapped = set()
    if isinstance(response_json, dict):
        for key, value in response_json.items():
            if key in COMPLIANCE_RULES:
                mapped.update(COMPLIANCE_RULES[key])
            # Recurse into nested dictionaries
            if isinstance(value, dict):
                mapped.update(auto_map_compliance(value))
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        mapped.update(auto_map_compliance(item))
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
            # Resolve view name
            try:
                resolved = resolve(request.path_info)
                current_view = resolved.url_name
            except Resolver404:
                return self.get_response(request)

            if current_view not in self.included_views:
                return self.get_response(request)

            # Fetch user memberships
            memberships = OrganizationManagement.objects.filter(user=request.user).select_related('organization')
            if not memberships:
                logger.warning(f"User {request.user.email} has no organization memberships")
                return JsonResponse({'message': 'You are not associated with any organization.'}, status=403)

            org_roles = {str(m.organization.id).replace('-', ''): m.role for m in memberships}
            organizations = [
                {
                    'id': str(m.organization.id).replace('-', ''),
                    'name': m.organization.name,
                    'role': m.role
                } for m in memberships
            ]
            request.user_organizations = organizations
            request.user_org_roles = org_roles

            # --- NEW CHECK 1: Ensure active organization exists ---
            try:
                profile = UserProfile.objects.get(user=request.user)
                active_org = profile.active_organization
            except UserProfile.DoesNotExist:
                active_org = None

            if not active_org:
                return JsonResponse({'message': 'Please set an active organization before running this scan.'}, status=403)

            # --- NEW CHECK 2: Ensure current view is allowed for active role ---
            membership = OrganizationManagement.objects.filter(
                user=request.user, organization=active_org
            ).first()
            active_role = membership.role if membership else None

            if not active_role or current_view not in role_based_views.get(active_role, []):
                return JsonResponse({'message': 'You are not allowed to access this scan.'}, status=403)

            # Proceed with the request
            response = self.get_response(request)

            # Log Scan in background
            def log_thread():
                try:
                    if response.status_code != 200:
                        return  # Only log successful responses

                    scan_name = self.view_display_names.get(current_view, current_view)

                    # Fetch active organization again for logging
                    try:
                        profile = UserProfile.objects.get(user=request.user)
                        organization = profile.active_organization
                    except UserProfile.DoesNotExist:
                        organization = None

                    if not organization:
                        logger.warning(f"User {request.user.email} has no active organization set")
                        return

                    # Fetch role for this organization
                    membership = OrganizationManagement.objects.filter(
                        user=request.user, organization=organization
                    ).first()
                    role = membership.role if membership else "none"

                    # Prepare JSON data
                    if hasattr(response, 'content') and response.get('Content-Type', '').startswith('application/json'):
                        try:
                            json_data = json.loads(response.content.decode('utf-8', errors='ignore'))
                        except json.JSONDecodeError:
                            json_data = {"error": "Failed to decode JSON response"}
                    else:
                        json_data = {"note": "No JSON content in response"}

                    # --- AUTO MAP COMPLIANCE ---
                    compliance_mappings = auto_map_compliance(json_data)

                    # --- CREATE NOTIFICATION BEFORE SAVING SCANLOG ---
                    Notification.objects.create(
                        email=request.user.email,
                        heading=f"Scan Completed: {scan_name}",
                        message=f"Your scan '{scan_name}' was completed successfully.",
                        actionable=False,
                        json_data=json_data,
                        type='Scan Completed',
                        organization_id=str(organization.id).replace('-', ''),
                    )

                    # --- SAVE SCANLOG ---
                    Scanlog.objects.create(
                        user=request.user,
                        scan_name=scan_name,
                        group='organization',
                        status_code=response.status_code,
                        organization=organization,
                        role=role,
                        timestamp=now(),
                        json_data=json_data,
                        compliance_mappings=compliance_mappings,  # ✅ store mapped compliance standards
                    )

                except Exception as log_error:
                    logger.error(f"Failed to log Scanlog/Notification: {str(log_error)}", exc_info=True)

            threading.Thread(target=log_thread).start()
            return response

        except Exception as e:
            log_exception(e)
            logger.error(f"Error in OrganizationContextMiddleware: {str(e)}", exc_info=True)
            return JsonResponse({'message': 'An error occurred while processing organization context.'}, status=500)
