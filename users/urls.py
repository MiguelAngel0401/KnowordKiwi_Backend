from django.urls import path
from .views import (
    CookieTokenRefreshView,
    LogoutView,
    RegisterView,
    LoginView,
    VerifyEmailView,
    CheckEmailAvailabilityView,
    CheckUsernameAvailabilityView,
    UserProfileView,
    #AvatarUploadView,
)

urlpatterns = [
    path("register/", RegisterView.as_view(), name="register"),
    path(
        "check-email/",
        CheckEmailAvailabilityView.as_view(),
        name="check-email-availability",
    ),
    path(
        "check-username/",
        CheckUsernameAvailabilityView.as_view(),
        name="check-username-availability",
    ),
    path("login/", LoginView.as_view(), name="login"),
    path("me/", UserProfileView.as_view(), name="user-profile"),
    #path("me/avatar/", AvatarUploadView.as_view(), name="avatar-upload"),
    path("verify-email/<str:token>/", VerifyEmailView.as_view(), name="verify-email"),
    path("token/refresh/", CookieTokenRefreshView.as_view(), name="token-refresh"),
    path("logout/", LogoutView.as_view(), name="logout"),
]
