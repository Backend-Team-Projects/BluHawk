from django.shortcuts import render

# Create your views here.
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.exceptions import TokenError
from django.contrib.auth.hashers import check_password, make_password

from session_management.models import Profile, Verification

from django.contrib.auth.models import User

from rest_framework_simplejwt.token_blacklist.models import (
    OutstandingToken,
    BlacklistedToken,
)

from django.contrib.auth.password_validation import validate_password

from django.core.cache import cache

from django.core.mail import send_mail
import uuid
from django.utils.timezone import now

from datetime import datetime, timedelta
from django.utils.timezone import now

from django.core.validators import validate_email
import random

from django.template.loader import render_to_string

from django.conf import settings
import traceback
from session_management.models import (
    OrganizationManagement,
    Organization,
    OrganizationInvitation,
)
from user_settings.models import UserProfile
from attack_surface.models import (
    Notification,
)
import uuid
import logging
logger = logging.getLogger(__name__)

from django.template.loader import get_template
from rest_framework.permissions import BasePermission
from django.shortcuts import get_object_or_404

from BluHawk.config import *
from BluHawk.utils import *

from attack_surface.models import Notification
from BluHawk import load_env as myenv


class IsAdminAndOrganizationAdmin(BasePermission):

    def has_permission(self, request, view):
        user = request.user

        # Get organization_id from all possible sources
        org_id_kwargs = view.kwargs.get("organization_id")
        org_id_data = request.data.get("organization_id")
        org_id_params = request.query_params.get("organization_id")

        # Collect all non-None org_ids
        org_ids = [org_id_kwargs, org_id_data, org_id_params]
        non_null_ids = [oid for oid in org_ids if oid is not None]

        # Case 1: All are None → allow
        if not non_null_ids:
            return True

        # Case 2: Provided values must match
        if len(set(non_null_ids)) > 1:
            return False

        # Case 3: Check org admin role using the unique org_id
        organization_id = non_null_ids[0]

        return OrganizationManagement.objects.filter(
            organization_id=organization_id,
            user=user,
            role='admin'  # Adjust if needed
        ).exists()


def is_updated_recently(updated_at):
    current_time = now()
    valid_until = updated_at + timedelta(minutes=5)
    return current_time <= valid_until


def generate_verification_code():
    return f"{random.randint(100000, 999999)}"


class AuthService:
    @staticmethod
    def sign_in_user(email, password):
        user = authenticate(username=email, password=password)
        if user is None:
            return None

        refresh = RefreshToken.for_user(user)
        return {"access": str(refresh.access_token), "refresh": str(refresh)}


def is_valid_email(email):
    try:
        validate_email(email)
        return True
    except ValidationError:
        return False


class SignupView(APIView):
    def post(self, request, *args, **kwargs):
        email = request.data.get("email")
        password = request.data.get("password")
        reenter_password = request.data.get("reenter_password")
        verification_key = request.data.get("verification_key")

        if not (password and reenter_password and email):
            return Response(
                {"message": "Missing signup details!", "status": "missing_details"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if password != reenter_password:
            return Response(
                {"message": "Passwords do not match.", "status": "password_error"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if User.objects.filter(email=email).exists():
            return Response(
                {
                    "message": "User with this email already exists.",
                    "status": "user_exists",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            validate_password(password)
        except ValidationError as e:
            return Response(
                {"message": list(e.messages)[0], "status": "weak_password"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if verification_key:
            try:
                valid = is_valid_email(email)
                if valid:

                    results = Verification.objects.filter(
                        email=email, verification_key=verification_key
                    )
                    if results.count():
                        if is_updated_recently(results[0].updated_at):

                            Verification.objects.filter(email=email).delete()
                            user = User.objects.create_user(
                                username=email, email=email, password=password
                            )
                            sign_in_data = AuthService.sign_in_user(email, password)
                            if not sign_in_data:
                                return Response(
                                    {"message": "Invalid credentials after signup."},
                                    status=status.HTTP_400_BAD_REQUEST,
                                )
                            from user_settings.models import UserProfile, UserSettings

                            UserProfile.objects.create(user=user, name = email.split('@')[0])
                            UserSettings.objects.create(user=user)

                            return Response(
                                {
                                    "message": "User created successfully!",
                                    "data": {
                                        "access_token": sign_in_data["access"],
                                        "refresh_token": sign_in_data["refresh"],
                                    },
                                    "status": "success",
                                },
                                status=status.HTTP_201_CREATED,
                            )

                        else:
                            return Response(
                                {
                                    "message": "Token expired, please regenerate a new token!",
                                    "status": "token_expired",
                                },
                                status=status.HTTP_400_BAD_REQUEST,
                            )

                    else:
                        return Response(
                            {
                                "message": "Invalid verification token, please check your email!",
                                "status": "invalid_verification_code",
                            },
                            status=status.HTTP_400_BAD_REQUEST,
                        )

                else:
                    return Response(
                        {
                            "message": "Invalid verification token!",
                            "status": "invalid_verification_code",
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            except IntegrityError:
                return Response(
                    {
                        "message": "User with this email already exists.",
                        "status": "user_exists",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            except Exception as e:
                return log_exception(e)
        else:
            try:
                key = generate_verification_code()
                verification = Verification.objects.create(
                    email=email, verification_key=key
                )
                verification.save()

                html_content = render_to_string("email_verification.html", {"key": key})

                send_mail(
                    "Email Verification for BluHawk",
                    f"Your verification key for BluHawk account creation is {key}",
                    fail_silently=True,
                    html_message=html_content,
                    from_email=myenv.ADMIN_EMAIL,
                    recipient_list=[email],
                    auth_user=myenv.EMAIL_HOST_USER,
                    auth_password=myenv.EMAIL_HOST_PASSWORD,
                )
                return Response(
                    {
                        "message": "successfully sent verification code to email.",
                        "status": "status",
                    },
                    status=status.HTTP_200_OK,
                )

            except Exception as e:
                return log_exception(e)


class SendVerificationToken(APIView):
    def post(self, request, *args, **kwargs):
        try:
            email = request.data.get("email")
            valid = is_valid_email(email)
            if not valid:
                return Response(
                    {
                        "message": "Invalid email, check your email and try again.",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            key = generate_verification_code()

            verification = Verification.objects.create(
                email=email, verification_key=key
            )
            verification.save()

            html_content = render_to_string("email_verification.html", {"key": key})

            send_mail(
                "Email Verification for BluHawk",
                f"Your verification key for BluHawk account creation is {key}",
                recipient_list=[email],
                fail_silently=True,
                html_message=html_content,
                from_email=myenv.ADMIN_EMAIL,
                auth_user=myenv.EMAIL_HOST_USER,
                auth_password=myenv.EMAIL_HOST_PASSWORD,
            )

            return Response(
                {
                    "message": "successfully sent verification code to email.",
                },
                status=status.HTTP_200_OK,
            )
        except Exception as e:
            return log_exception(e)


class SigninView(APIView):
    def post(self, request, *args, **kwargs):
        email = request.data.get("email")
        password = request.data.get("password")

        if not (email and password):
            return Response(
                {"message": "Missing signin details!"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            user = authenticate(request, username=email, password=password)

            if user is None:
                return Response(
                    {"message": "Invalid credentials!"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            
            from user_settings.models import UserProfile, UserSettings

            if UserSettings.objects.filter(user=user).exists():
                user_settings = UserSettings.objects.get(user=user)
            else:
                user_settings = UserSettings.objects.create(user=user)
            
            if user_settings.two_factor_auth_enabled:
                cache.set(f'2fa:{user.email}', random.randint(100000, 999999), timeout=300)

                html_content = render_to_string(
                    "2_factor_authentication.html",
                    {
                        "verification_code": cache.get(f'2fa:{user.email}'),
                    },
                )
                

                send_mail(
                    "Two Factor Authentication Code",
                    f"Your two-factor authentication code is: {cache.get(f'2fa:{user.email}')}",
                    recipient_list=[user.email],
                    from_email=myenv.ADMIN_EMAIL,
                    auth_user=myenv.EMAIL_HOST_USER,
                    auth_password=myenv.EMAIL_HOST_PASSWORD,
                    fail_silently=True,
                    html_message=html_content,
                )

                return Response(
                    {
                        "2fa_enabled": True,
                        "email": user.email,
                        "message": "Two-factor authentication is enabled for this account. Please provide the verification code.",
                    }
                )
                

            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)

            return Response(
                {
                    "message": "Successfully signed in!",
                    "data": {
                        "access_token": access_token,
                        "refresh_token": str(refresh),
                    },
                },
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            return log_exception(e)

class VerifyTwoFactorView(APIView):
    def post(self, request, *args, **kwargs):
        email = request.data.get("email")
        verification_code = request.data.get("verification_code")
        if not (email and verification_code):
            return Response(
                {"message": "Email and verification code are required!"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            cached_code = cache.get(f'2fa:{email}')
            if not cached_code:
                return Response(
                    {"message": "Verification code expired or invalid."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if str(cached_code) != str(verification_code):
                return Response(
                    {"message": "Invalid verification code."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            user = User.objects.get(email=email)
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)

            # Clear the cached verification code
            cache.delete(f'2fa:{email}')

            return Response(
                {
                    "message": "Two-factor authentication successful!",
                    "data": {
                        "access_token": access_token,
                        "refresh_token": str(refresh),
                    },
                },
                status=status.HTTP_200_OK,
            )

        except User.DoesNotExist:
            return Response(
                {"message": "User not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        except Exception as e:
            return log_exception(e)


class SignoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):

        try:
            refresh_token = request.data.get("refresh")
            if not refresh_token:
                return Response(
                    {"message": "Refresh token is required!"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            try:
                token = RefreshToken(refresh_token)
                token.blacklist()

                return Response(
                    {"message": "Successfully logged out!"}, status=status.HTTP_200_OK
                )

            except Exception as e:
                return Response(
                    {"message": "Invalid refresh token."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        except Exception as e:
            return log_exception(e)


class RefreshTokenView(APIView):
    def post(self, request, *args, **kwargs):
        refresh_token = request.data.get("refresh")

        if not refresh_token:
            return Response(
                {"message": "Refresh token is required!"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            refresh = RefreshToken(refresh_token)
            access_token = str(refresh.access_token)

            return Response(
                {"access_token": access_token, "refresh_token": str(refresh)},
                status=status.HTTP_200_OK,
            )

        except TokenError as e:
            return Response(
                {"message": "Invalid refresh token!"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as e:
            return log_exception(e)


class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        user = request.user
        old_password = request.data.get("old_password")
        new_password = request.data.get("new_password")
        confirm_password = request.data.get("confirm_password")

        if not old_password or not new_password or not confirm_password:
            return Response(
                {"message": "All fields are required!"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if new_password != confirm_password:
            return Response(
                {"message": "New passwords do not match!"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            validate_password(new_password)
        except ValidationError as e:
            return Response(
                {"message": list(e.messages)[0]}, status=status.HTTP_400_BAD_REQUEST
            )

        if not check_password(old_password, user.password):
            return Response(
                {"message": "Old password is incorrect!"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            user.set_password(new_password)
            user.save()

            tokens = OutstandingToken.objects.filter(user=user)
            for token in tokens:
                try:
                    BlacklistedToken.objects.get_or_create(token=token)
                except Exception:
                    continue

            return Response(
                {
                    "message": "Password changed successfully, and all tokens have been invalidated."
                },
                status=status.HTTP_200_OK,
            )
        except Exception as e:
            return log_exception(e)


class ForgottenPasswordView(APIView):
    def post(self, request, *args, **kwargs):
        email = request.data.get("email")

        if not email:
            return Response(
                {"message": "Email is required!"}, status=status.HTTP_400_BAD_REQUEST
            )

        try:
            user = User.objects.get(email=email)
            reset_token = str(uuid.uuid4())

            user.profile.reset_token = reset_token
            user.profile.reset_token_created_at = now()
            user.profile.save()

            reset_url = f"{myenv.site_domain}reset-password/{reset_token}"

            html_content = render_to_string(
                "reset_password_email.html", {"reset_link": reset_url}
            )

            send_mail(
                "Password Reset Request",
                f"Click the link below to reset your password:\n\n{reset_url}",
                recipient_list=[email],
                fail_silently=True,
                html_message=html_content,
                from_email=myenv.ADMIN_EMAIL,
                auth_user=myenv.EMAIL_HOST_USER,
                auth_password=myenv.EMAIL_HOST_PASSWORD,
            )

            return Response(
                {"message": "Password reset link sent to your email!"},
                status=status.HTTP_200_OK,
            )

        except User.DoesNotExist:
            return Response(
                {"message": "No user found with this email!"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as e:
            return log_exception(e)


class ResetPasswordView(APIView):
    def post(self, request, token, *args, **kwargs):
        new_password = request.data.get("new_password")
        confirm_password = request.data.get("confirm_password")

        if not (new_password and confirm_password):
            return Response(
                {"message": "Both password fields are required!"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if new_password != confirm_password:
            return Response(
                {"message": "Passwords do not match!"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            validate_password(new_password)
        except ValidationError as e:
            return Response(
                {"message": list(e.messages)[0]}, status=status.HTTP_400_BAD_REQUEST
            )

        try:
            profile = Profile.objects.get(reset_token=token)

            if not profile.is_reset_token_valid():
                return Response(
                    {"message": "The reset token is invalid or expired."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            user = profile.user
            user.set_password(new_password)
            user.save()

            tokens = OutstandingToken.objects.filter(user=user)
            for token in tokens:
                try:
                    BlacklistedToken.objects.get_or_create(token=token)
                except Exception as e:
                    continue

            profile.reset_token = None
            profile.reset_token_created_at = None
            profile.save()

            return Response(
                {"message": "Password has been reset successfully!"},
                status=status.HTTP_200_OK,
            )

        except Profile.DoesNotExist:
            return Response(
                {"message": "Invalid reset token!"}, status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            return log_exception(e)

from django.contrib.auth.models import User
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from google.oauth2 import id_token
from google.auth.transport import requests
from rest_framework_simplejwt.tokens import RefreshToken

class GoogleSigninView(APIView):
    def post(seluintf, request):
        token = request.data.get('token')
        if not token:
            return Response({'error': 'Token is required'}, status=400)

        try:
            CLIENT_ID = "912671894848-14cm1r3v14la0uq3h76q47t5llfplm97.apps.googleusercontent.com"
            idinfo = id_token.verify_oauth2_token(token, requests.Request(), CLIENT_ID)
            
            email = idinfo['email']
            first_name = idinfo.get('given_name', '')
            last_name = idinfo.get('family_name', '')

            user, created = User.objects.get_or_create(email=email, defaults={
                'username': email,
                'first_name': first_name,
                'last_name': last_name,
            })
            

            refresh = RefreshToken.for_user(user)
            

            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name
                }
            })

        except ValueError as e:
            print(f"ValueError: {e}")
            return Response({'error': 'Invalid token'}, status=400)






class GetUserOrganization(APIView):
    permission_classes = [IsAuthenticated ,IsAdminAndOrganizationAdmin]

    def get(self, request, *args, **kwargs):
        user = request.user
        try:
            organization_memberships = OrganizationManagement.objects.filter(
                user=user
            ).values("organization_id", "role")

            org_roles = {
                membership["organization_id"]: membership["role"]
                for membership in organization_memberships
            }

            organizations = list(
                Organization.objects.filter(id__in=org_roles.keys()).values()
            )

            for org in organizations:
                org["role"] = org_roles[org["id"]]

            return Response(
                {"organization": organizations},
                status=status.HTTP_200_OK,
            )
        except Exception as e:
            log_exception(e)
            logger.error(f"Error getting user organizations: {str(e)}", exc_info=True)
            return Response(
                {"message": "An error occurred."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

class CreateOrganization(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        user = request.user
        name = request.data.get("name")
        address = request.data.get("address")
        country = request.data.get("country")
        logo_url = request.data.get("logo_url")

        if not (name and address and country):
            return Response(
                {"message": "All fields are required!"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            organization = Organization.objects.create(
                id=str(uuid.uuid4()).replace("-", "")[:16],
                name=name,
                address=address,
                email=user.email,
                country=country,
                logo_url=logo_url,
            )

            OrganizationManagement.objects.create(
                organization=organization, user=user, role="admin"
            )

            return Response(
                {"message": "Organization created successfully!"},
                status=status.HTTP_201_CREATED,
            )
        except IntegrityError:
            return Response(
                {"message": "Organization with this email already exists."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as e:
            log_exception(e)
            logger.error(f"Error creating organization: {str(e)}", exc_info=True)
            return Response(
                {"message": "An error occurred."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        


class DeleteOrganization(APIView):
    permission_classes = [IsAuthenticated , IsAdminAndOrganizationAdmin]

    def delete(self, request, *args, **kwargs):
        user = request.user
        organization_id = kwargs.get("organization_id")

        if not organization_id:
            return Response(
                {"message": "Organization ID is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            # Check if the user is an admin of the organization
            membership = OrganizationManagement.objects.filter(
                organization_id=organization_id,
                user=user,
                role="admin"
            ).first()

            if not membership:
                return Response(
                    {"message": "You are not authorized to delete this organization."},
                    status=status.HTTP_403_FORBIDDEN,
                )

            with transaction.atomic():
                # Delete the organization and cascade related entries
                Organization.objects.filter(id=organization_id).delete()

            return Response(
                {"message": "Organization deleted successfully."},
                status=status.HTTP_200_OK,
            )
        except Exception as e:
            log_exception(e)
            logger.error(f"Error deleting organization: {str(e)}", exc_info=True)
            return Response(
                {"message": "An error occurred while deleting the organization."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


from BluHawk.config import allowed_roles
class InviteUserToOrganization(APIView):
    permission_classes = [IsAuthenticated , IsAdminAndOrganizationAdmin]

    def post(self, request, *args, **kwargs):
        email = request.data.get("email")
        organization_id = request.data.get("organization_id")
        role = request.data.get("role")

        # Validate required fields
        if not (email and organization_id and role):
            return Response({"message": "All fields are required!"}, status=status.HTTP_400_BAD_REQUEST)

        if role not in allowed_roles:
            return Response(
                {"message": f"Invalid role! Must be one of: {', '.join(allowed_roles)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            organization = Organization.objects.get(id=organization_id)
        except Organization.DoesNotExist:
            return Response({"message": "Organization does not exist!"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Generate unique verification token
            verification_code = uuid.uuid4().hex
            verification_url = f"{myenv.site_domain}invitation/{verification_code}"

            # Email content (HTML and plain text)
            html_content = render_to_string("organization_invitation.html", {
                "organization": organization.name,
                "verification_url": verification_url,
                "role": role,
            })

            # Send email to invited user
            send_mail(
                subject="You're invited to join an organization",
                message=f"You've been invited to join {organization.name} as {role}. Click the link: {verification_url}",
                from_email=myenv.ADMIN_EMAIL,
                auth_user=myenv.EMAIL_HOST_USER,
                auth_password=myenv.EMAIL_HOST_PASSWORD,
                recipient_list=[email],
                html_message=html_content,
                fail_silently=False
            )

            # Create actionable notification (for invited user)
            Notification.objects.create(
                email=email,
                heading=f"Invitation to {organization.name}",
                message=f"You have been invited to join {organization.name} as a {role}.",
                actionable=True,
                json_data={
                    "organization_name": organization.name,
                    "role": role,
                    "verification_code": verification_code,
                    "invited_by": request.user.email  # ✅ Add inviter info
                },
                type="invitation",
                organization_id=organization.id,
                action_status="pending"
            )

            # Save the invitation with invited_by field (if it exists in the model)
            OrganizationInvitation.objects.create(
                organization=organization,
                email=email,
                verification_code=verification_code,
                role=role,
                invited_by=request.user  # ✅ Ensure this field exists in model
            )

            return Response({"message": "Invitation sent successfully!"}, status=status.HTTP_200_OK)

        except Exception as e:
            log_exception(e)
            logger.error(f"Error sending invitation: {str(e)}", exc_info=True)
            return Response({"message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

from BluHawk.utils import log_exception

class GetOrganizationInvitationDetails(APIView):
    permission_classes = []

    def get(self, request, token):
        try:
            invitation = OrganizationInvitation.objects.get(
                verification_code=token,
                status="pending"
            )

            return Response({
                "email": invitation.email,
                "role": invitation.role,
                "organization_name": invitation.organization.name,
                "admin_email": invitation.organization.email
            }, status=status.HTTP_200_OK)

        except OrganizationInvitation.DoesNotExist as e:
            log_exception(e)
            return Response({"message": "Invalid or expired invitation."}, status=status.HTTP_400_BAD_REQUEST)

        


class VerifyOrganizationInvitation(APIView):
    permission_classes = []

    def post(self, request, *args, **kwargs):
        token = request.data.get("token")
        action = request.data.get("action")  # "accept" or "reject"

        if not (token and action in ["accept", "reject"]):
            return Response(
                {"message": "Token and valid action are required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            invitation = OrganizationInvitation.objects.get(
                verification_code=token,
                status="pending"
            )
            organization = invitation.organization

            # Fetch inviter from original notification
            try:
                notification = Notification.objects.get(
                    email=invitation.email,
                    type="invitation",
                    json_data__verification_code=token
                )
                inviter_email = notification.json_data.get("invited_by")
                notification.action_status = action
                notification.save()
            except Notification.DoesNotExist:
                notification = None
                inviter_email = None

            if action == "reject":
                invitation.status = "rejected"
                invitation.save()
            else:
                try:
                    user = User.objects.get(email=invitation.email)
                except User.DoesNotExist:
                    return Response(
                        {"message": "User does not exist. Please register first."},
                        status=status.HTTP_403_FORBIDDEN
                    )

                already_exists = OrganizationManagement.objects.filter(
                    organization=organization,
                    user=user
                ).exists()

                if not already_exists:
                    OrganizationManagement.objects.create(
                        organization=organization,
                        user=user,
                        role=invitation.role
                    )

                invitation.status = "accepted"
                invitation.save()

            # Send email and create notification to all admins
            admin_users = OrganizationManagement.objects.filter(
                organization=organization,
                role="admin"
            ).select_related("user")

            for admin in admin_users:
                is_inviter = (admin.user.email == inviter_email)
                template = (
                    "invitation_status_inviter.html" if is_inviter else "invitation_status_others.html"
                )

                send_mail(
                    subject=f"Invitation {action.capitalize()} by {invitation.email}",
                    message=None,
                    from_email=myenv.ADMIN_EMAIL,
                    auth_user=myenv.EMAIL_HOST_USER,
                    auth_password=myenv.EMAIL_HOST_PASSWORD,
                    recipient_list=[admin.user.email],
                    html_message=render_to_string(template, {
                        "invitee_email": invitation.email,
                        "organization_name": organization.name,
                        "status": action,
                        "role": invitation.role,
                        "invited_by": inviter_email if not is_inviter else None
                    }),
                    fail_silently=False
                )

                # Create notification for all admins
                heading = f"Invitation {action.capitalize()}"
                if is_inviter:
                    message = f"{invitation.email} has {action}ed your invitation to join {organization.name} as {invitation.role}."
                else:
                    message = f"{invitation.email} has {action}ed the invitation sent by {inviter_email} to join {organization.name} as {invitation.role}."

                Notification.objects.create(
                    email=admin.user.email,
                    heading=heading,
                    message=message,
                    actionable=False,
                    json_data={
                        "invitee_email": invitation.email,
                        "verification_code": invitation.verification_code,
                        "status": action,
                        "role": invitation.role,
                        "invited_by": inviter_email
                    },
                    type="invitation status",
                    organization_id=organization.id,
                    seen=False,
                    action_status=action
                )

            return Response({"message": f"Invitation {action}ed."}, status=status.HTTP_200_OK)

        except OrganizationInvitation.DoesNotExist:
            return Response(
                {"message": "Invalid or expired invitation."},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            log_exception(e)
            logger.error(f"Error verifying invitation: {str(e)}", exc_info=True)
            return Response(
                {"message": "Something went wrong."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )



class InvitationManagement(APIView):
    permission_classes = [IsAuthenticated , IsAdminAndOrganizationAdmin]

    def delete(self, request, *args, **kwargs):
        org_id = kwargs.get("organization_id")
        email = request.data.get("email")  # Optional: for targeting a specific invitee

        if not org_id:
            return Response({"message": "Missing organization ID!"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            organization = get_object_or_404(Organization, id=org_id)

            if email:
                # Delete a specific pending invitation for the given email
                invitation = OrganizationInvitation.objects.filter(
                    organization=organization,
                    email=email,
                    status="pending"
                ).first()

                if not invitation:
                    return Response({"message": "No pending invitation found for this email."}, status=status.HTTP_404_NOT_FOUND)

                invitation.delete()
                logger.info(f"Invitation for {email} deleted by {request.user.email} for org {organization.name}")

                return Response(
                    {"message": f"Pending invitation for {email} deleted successfully."},
                    status=status.HTTP_200_OK
                )

            else:
                # Delete all pending invitations
                deleted_count, _ = OrganizationInvitation.objects.filter(
                    organization=organization,
                    status="pending"
                ).delete()

                logger.info(f"{deleted_count} pending invitations deleted by {request.user.email} for organization {organization.name}")

                return Response(
                    {"message": f"{deleted_count} pending invitations deleted successfully."},
                    status=status.HTTP_200_OK
                )

        except Exception as e:
            log_exception(e)
            logger.error(f"Error managing invitations: {str(e)}", exc_info=True)
            return Response(
                {"message": "An error occurred while processing the request."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ManageOrganization(APIView):
    permission_classes = [IsAuthenticated, IsAdminAndOrganizationAdmin]

    def get(self, request, *args, **kwargs):
        org_id = kwargs.get("organization_id")

        if not org_id:
            return Response({"message": "Missing organization ID!"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            organization = get_object_or_404(Organization, id=org_id)
            organization_data = {
                "id": organization.id,
                "name": organization.name,
                "address": organization.address,
                "email": organization.email,
                "country": organization.country,
                "logo_url": organization.logo_url,
            }

            # Members
            members_qs = OrganizationManagement.objects.filter(
                organization=organization
            ).values("user__email", "role")
            organization_data["members"] = list(members_qs)

            # Only pending Invitations
            invites_qs = OrganizationInvitation.objects.filter(
                organization=organization, status="pending"
            ).values("email", "role", "updated_at", "status")

            organization_data["invitations"] = list(invites_qs)

            return Response({"organization": organization_data}, status=status.HTTP_200_OK)

        except Exception as e:
            log_exception(e)
            logger.error(f"Error retrieving organization: {str(e)}", exc_info=True)
            return Response({"message": "An error occurred while retrieving the organization."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request, *args, **kwargs):
        org_id = kwargs.get("organization_id")
        mode = request.data.get("mode")

        if not org_id:
            return Response({"message": "Missing organization ID!"}, status=status.HTTP_400_BAD_REQUEST)

        if mode not in ["update_organization", "update_members"]:
            return Response({"message": "Invalid mode! Use 'update_organization' or 'update_members'."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            organization = get_object_or_404(Organization, id=org_id)

            if mode == "update_organization":
                allowed_fields = ["name", "address", "email", "country", "logo_url"]
                update_data = {field: request.data[field] for field in allowed_fields if field in request.data}

                with transaction.atomic():
                    for key, value in update_data.items():
                        setattr(organization, key, value)
                    organization.save()

                logger.info(f"Organization {organization.name} updated by {request.user.email}")
                return Response({"message": "Organization details updated successfully!"}, status=status.HTTP_200_OK)

            elif mode == "update_members":
                members = request.data.get("members", [])
                if not isinstance(members, list) or not members:
                    return Response({"message": "Invalid members data! Provide a list of users with actions."}, status=status.HTTP_400_BAD_REQUEST)

                emails = [m.get("user_email") for m in members if m.get("user_email")]
                if len(emails) != len(set(emails)):
                    return Response({"message": "Duplicate user emails detected in members list!"}, status=status.HTTP_400_BAD_REQUEST)

                updated_members = []
                removed_members = []
                errors = []

                for member in members:
                    action = member.get("action")
                    user_email = member.get("user_email")
                    role = member.get("role", "viewer").lower()

                    if action not in ["update", "remove"]:
                        errors.append({"user_email": user_email, "error": "Invalid action"})
                        continue

                    if not user_email:
                        errors.append({"user_email": "Unknown", "error": "Missing user_email"})
                        continue

                    try:
                        user = User.objects.get(email=user_email)
                    except User.DoesNotExist:
                        errors.append({"user_email": user_email, "error": "User not found"})
                        continue

                    org_member = OrganizationManagement.objects.filter(
                        organization=organization, user=user
                    ).first()

                    if not org_member:
                        errors.append({"user_email": user_email, "error": "User is not a member"})
                        continue

                    other_admins_count = OrganizationManagement.objects.filter(
                        organization=organization, role="admin"
                    ).exclude(user=user).count()

                    if action == "update":
                        if role not in allowed_roles:
                            errors.append({"user_email": user_email, "error": f"Invalid role! Must be one of: {', '.join(allowed_roles)}"})
                            continue

                        if org_member.role == "admin" and role != "admin" and other_admins_count == 0:
                            errors.append({"user_email": user_email, "error": "Cannot downgrade the only admin"})
                            continue

                        with transaction.atomic():
                            old_role = org_member.role
                            org_member.role = role
                            org_member.save()

                        updated_members.append(user_email)
                        logger.info(f"User {user_email} role changed from {old_role} to {role} in organization {organization.name} by {request.user.email}")

                    elif action == "remove":
                        if org_member.role == "admin" and other_admins_count == 0:
                            errors.append({"user_email": user_email, "error": "Cannot remove the only admin"})
                            continue

                        with transaction.atomic():
                            deleted, _ = OrganizationManagement.objects.filter(
                                organization=organization, user=user
                            ).delete()

                        if deleted:
                            removed_members.append(user_email)
                            logger.info(f"User {user_email} removed from organization {organization.name} by {request.user.email}")
                        else:
                            errors.append({"user_email": user_email, "error": "User is not a member"})

                response_data = {"message": "Bulk operation completed!"}
                if updated_members:
                    response_data["updated"] = updated_members
                if removed_members:
                    response_data["removed"] = removed_members
                if errors:
                    response_data["errors"] = errors

                return Response(response_data, status=status.HTTP_200_OK)

        except Exception as e:
            log_exception(e)
            logger.error(f"Error managing organization: {str(e)}", exc_info=True)
            return Response({"message": "An error occurred while managing the organization."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class NotificationAPIView(APIView):
    permission_classes = [IsAuthenticated ]

    def get(self, request):
        try:
            email = request.user.email
            unseen = request.query_params.get("unseen") == "true"
            see_more = request.query_params.get("see_more") == "true"
            offset = int(request.query_params.get("offset", 0))
            limit = 15 if see_more else 5

            base_qs = Notification.objects.filter(email=email)
            if unseen:
                base_qs = base_qs.filter(seen=False)

            total_count = base_qs.count()
            notifications = base_qs.order_by("-created_at")[offset:offset + limit]

            # Identify only unseen onesdf
            unseen_ids = [n.id for n in notifications if not n.seen]
            if unseen_ids:
                Notification.objects.filter(id__in=unseen_ids).update(seen=True)

            data = [
                {
                    "id": n.id,
                    "heading": n.heading,
                    "message": n.message,
                    "type": n.type,
                    "seen": True if n.id in unseen_ids else n.seen,
                    "actionable": n.actionable,
                    "action_status": n.action_status,
                    "json_data": n.json_data,
                    "organization_id": n.organization_id,
                    "created_at": n.created_at
                }
                for n in notifications
            ]

            return Response({
                "notifications": data,
                "has_more": offset + limit < total_count,
                "total_count": total_count
            }, status=200)
        except Exception as e:
            log_exception(e)
            logger.error(f"Error fetching notifications: {str(e)}", exc_info=True)
            return Response({"message": "An error occurred while fetching notifications."}, status=500)

    def delete(self, request):
        try:
            clear_all = request.query_params.get("clear_all") == "true"
            email = request.user.email

            if clear_all:
                deleted_count, _ = Notification.objects.filter(email=email).delete()
                return Response({"message": f"All {deleted_count} notifications deleted."}, status=200)

            notif_id = request.data.get("id")
            if not notif_id:
                return Response({"message": "Notification ID is required."}, status=400)

            try:
                notification = Notification.objects.get(id=notif_id, email=email)
                notification.delete()
                return Response({"message": "Notification deleted."}, status=200)
            except Notification.DoesNotExist:
                return Response({"message": "Notification not found."}, status=404)
            
        except Exception as e:
            log_exception(e)
            logger.error(f"Error deleting notification: {str(e)}", exc_info=True)
            return Response({"message": "An error occurred while deleting the notification."}, status=500)
        


class CheckUnseenNotificationsAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            email = request.user.email

            # Fetch unseen notifications of type "Scan Completed", newest first
            scan_notifications = Notification.objects.filter(
                email=email,
                seen=False,
                type__icontains="Scan Completed"
            ).order_by("-created_at")

            count = scan_notifications.count()
            data = []

            if count:
                # Prepare data to return
                data = [
                    {
                        "id": n.id,
                        "heading": n.heading,
                        "message": n.message,
                        "type": n.type,
                        "seen": True,  # Will be marked as seen
                        "actionable": n.actionable,
                        "json_data": n.json_data,
                        "organization_id": n.organization_id,
                        "created_at": n.created_at
                    }
                    for n in scan_notifications
                ]

                # Mark notifications as seen
                scan_notifications.update(seen=True)

            # Fetch total unseen count for other notifications
            unseen_count = Notification.objects.filter(email=email, seen=False).count()

            return Response({
                "notifications": data,
                "message": "Scan notifications fetched and marked as seen." if count else "No scan notifications.",
                "count": count,
                "unseen_count": unseen_count
            }, status=200)

        except Exception as e:
            logger.error(f"Error checking unseen notifications: {str(e)}", exc_info=True)
            return Response({"message": "An error occurred while checking unseen notifications."}, status=500)



class SetActiveOrganization(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        org_id = request.data.get("organization_id")
        if not org_id:
            return Response({"message": "Missing organization ID"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            organization = Organization.objects.get(id=org_id)
        except Organization.DoesNotExist:
            return Response({"message": "Organization not found"}, status=status.HTTP_404_NOT_FOUND)

        # Check membership
        is_member = OrganizationManagement.objects.filter(
            organization=organization, user=request.user
        ).exists()
        if not is_member:
            return Response({"message": "You are not a member of this organization"}, status=status.HTTP_403_FORBIDDEN)

        # Update active organization
        profile, _ = UserProfile.objects.get_or_create(user=request.user)
        profile.active_organization = organization
        profile.save()

        return Response({"message": f"Active organization set to {organization.name}"}, status=status.HTTP_200_OK)
