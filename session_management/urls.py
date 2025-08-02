
from django.contrib import admin
from django.urls import path
from session_management.views import *

urlpatterns = [
    path("google-signin", GoogleSigninView.as_view(), name="google_signin"),
    path('signup', SignupView.as_view(), name='signup'),
    path('signin', SigninView.as_view(), name='signin'),
    path('signout', SignoutView.as_view(), name='signout'),
    path('change_password', ChangePasswordView.as_view(), name='change_password'),
    path("forgotten_password", ForgottenPasswordView.as_view(), name='forgotten_password'),
    path("refresh_access", RefreshTokenView.as_view(), name='refresh_access'),
    path("send_verification", SendVerificationToken.as_view(), name='send_verification'),
    path("reset_password/<str:token>", ResetPasswordView.as_view(), name="reset_password"),
    path("create_organization", CreateOrganization.as_view()),
    path("get_organizations", GetUserOrganization.as_view()),
    path("organization/<str:organization_id>/", ManageOrganization.as_view(), name="manage-organization"),
    path("organizations/<str:organization_id>/invite/", InviteUserToOrganization.as_view(), name="invite_user_to_organization"),
    path("organization/verify-invitation", VerifyOrganizationInvitation.as_view(), name="verify_organization_invitation"),
    path('invitation/details/<str:token>/', GetOrganizationInvitationDetails.as_view(), name='get-invite-details'),
    path('organizations/<str:organization_id>/delete/', DeleteOrganization.as_view(), name='delete-organization'),
    path('invitation_manage/<str:organization_id>/', InvitationManagement.as_view(), name='invitation-manage'),
    path('notifications/', NotificationAPIView.as_view(), name='notification_list'),
    path('notifications/unseen-status/', CheckUnseenNotificationsAPIView.as_view(), name='check-unseen'),

    # 2fa
    path('2fa_verification/', VerifyTwoFactorView.as_view(), name='2fa_verification'),
] 