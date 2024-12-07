from django.contrib import admin
from .views import *
from django.urls import path,include

from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView
)
 
 
 

urlpatterns = [
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('register/',  RegisterView.as_view(), name='register'),
    path('verify/', RegisterVerifyOTPView.as_view(), name='verify-otp'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    path('login/', LoginView.as_view(), name='login'),
    path('forgot-password/', ForgotPasswordView.as_view(), name='forgot-password'),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify-otp'),
    path('reset-password/', PasswordResetView.as_view(), name='reset-password'),
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),
    path('plans/', get_all_plans, name='get_all_plans'),
    path('plan/<int:plan_id>/',PlanDetail.as_view(),name="PlanDetail"),
    path('plan-status/', check_plan_status, name='check_plan_status'),
    path('create-payment-intent/', create_payment_intent, name='create-payment-intent'),
    path("paymentpage/",paymentpage,name="paymentpage"),
    path('paypal/create/', PaypalPaymentView.as_view(), name='ordercreate'),
    path('paypal/validate/', PaypalValidatePaymentView.as_view(), name='paypalvalidate'),
    path('my-profile/', GetProfileView.as_view(), name='get-profile'),
    path('edit-profile/', ProfileUpdateView.as_view(), name='profile-update'),
    path('contact/',ContactUsView.as_view(),name='contact'),
    path('verify_payment/',verify_payment,name="verify_payment"),
    path('planexpired/',PlanExpiryHundler.as_view(),name="planexpired"),
    path('generate/', HixAPIHandler.as_view(), name='hix-api'),
    #path('generate/', GenerateTextView.as_view(), name='generate_text'),
    
]
    


 