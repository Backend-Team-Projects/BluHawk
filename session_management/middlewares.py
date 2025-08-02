import json
import logging
import threading
import uuid
from django.http import JsonResponse
from django.urls import resolve, Resolver404
from django.utils.timezone import now
from .models import OrganizationManagement, Scanlog, Organization
from BluHawk.config import view_display_pairs
from BluHawk.utils import *

logger = logging.getLogger(__name__)

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

            organization_id = request.headers.get('X-Organization-ID') or request.headers.get('x-organization-id')
            organization = None
            normalized_org_id = None
            if organization_id:
                try:
                    normalized_org_id = str(uuid.UUID(organization_id)).replace('-', '') if '-' in organization_id else organization_id
                    if normalized_org_id not in org_roles:
                        return JsonResponse({'message': 'You do not have access to this organization.'}, status=403)
                    organization = Organization.objects.get(id=uuid.UUID(organization_id) if '-' in organization_id else organization_id)
                except (ValueError, uuid.UUID):
                    return JsonResponse({'message': 'Invalid organization ID.'}, status=400)
                except Organization.DoesNotExist:
                    return JsonResponse({'message': 'Organization not found.'}, status=404)
            else:
                if memberships:
                    organization = memberships[0].organization
                    normalized_org_id = str(organization.id).replace('-', '')

            response = self.get_response(request)

            def log_thread():
                try:
                    if not organization or response.status_code != 200:
                        return  # Only log if organization exists and status code is 200

                    scan_name = self.view_display_names.get(current_view, current_view)

                    log = Scanlog(
                        user=request.user,
                        scan_name=scan_name,
                        group='organization',
                        status_code=response.status_code,
                        organization=organization,
                        role=org_roles.get(normalized_org_id, 'none'),
                        timestamp=now()
                    )

                    if hasattr(response, 'content') and response.get('Content-Type', '').startswith('application/json'):
                        try:
                            log.json_data = json.loads(response.content.decode('utf-8', errors='ignore'))
                        except json.JSONDecodeError:
                            log.json_data = {"error": "Failed to decode JSON response"}
                    else:
                        log.json_data = {"note": "No JSON content in response"}

                    log.save()
                except Exception as log_error:
                    logger.error(f"Failed to log Scanlog: {str(log_error)}", exc_info=True)

            threading.Thread(target=log_thread).start()
            return response

        except Exception as e:
            log_exception(e)
            logger.error(f"Error in OrganizationContextMiddleware: {str(e)}", exc_info=True)
            return JsonResponse({'message': 'An error occurred while processing organization context.'}, status=500)
