from django.contrib import admin
from .views import *
from django.urls import path,include

from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView
)
 
 
 

urlpatterns = [
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/register/', RegisterView.as_view(), name='register'),
    path('api/verify/', RegisterVerifyOTPView.as_view(), name='verify-otp'),
    path('api/token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    path('api/login/', LoginView.as_view(), name='login'),
    path('api/forgot-password/', ForgotPasswordView.as_view(), name='forgot-password'),
    path('api/verify-otp/', VerifyOTPView.as_view(), name='verify-otp'),
    path('api/reset-password/', PasswordResetView.as_view(), name='reset-password'),
    path('api/change-password/', ChangePasswordView.as_view(), name='change-password'),
    path('api/plans/', get_all_plans, name='get_all_plans'),
    path('api/plan-status/', check_plan_status, name='check_plan_status'),
    path('api/create-payment-intent/', create_payment_intent, name='create-payment-intent'),
    path('api/my-profile/', GetProfileView.as_view(), name='get-profile'),
    path('api/edit-profile/', ProfileUpdateView.as_view(), name='profile-update'),
    path('api/contact/', ContactUsView.as_view(), name='contact'),
    path('api/verify_payment/', verify_payment, name="verify_payment"),
    path('api/planexpired/', PlanExpiryHundler.as_view(), name="planexpired"),
    path('api/generate/', HixAPIHandler.as_view(), name='hix-api'),
    path('api/ai-detector/', ai_detector, name="ai_detector"),
]
