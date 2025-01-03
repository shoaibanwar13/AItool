from django.shortcuts import render
from .serializers import * 
from .models import *
import stripe
from rest_framework.decorators import api_view, permission_classes
from django.contrib.auth.models import User
 
from rest_framework import status
from django.contrib.auth import authenticate
import random
from django.core.mail import send_mail
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils import timezone
from .models import OTPVerification
from rest_framework import status
from rest_framework.views import APIView
from rest_framework import permissions
from django.contrib.auth.models import User
from rest_framework.decorators import api_view
from django.utils.timezone import now
from rest_framework.permissions import IsAuthenticated
from django.views.decorators.csrf import csrf_exempt
import json
from django.http import JsonResponse
from rest_framework import permissions
from  .utlis  import make_paypal_payment, verify_paypal_payment
from django.conf import settings
from rest_framework.parsers import MultiPartParser, FormParser
from django.utils.timezone import now
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from dj_rest_auth.registration.views import SocialLoginView
from django.db.models import F
import requests
import time
import os
from rest_framework.response import Response
from gradio_client import Client
# from rest_framework.exceptions import APIException
# from nltk.corpus import wordnet
# from nltk.tokenize import word_tokenize
# from nltk.tag import pos_tag
# import nltk
# import requests
# import random
# from textblob import TextBlob
# from django.conf import settings
# from rest_framework.views import APIView
# from rest_framework.response import Response
# from rest_framework.exceptions import APIException
# from rest_framework import status
# import time
# # Ensure nltk resources are downloaded
# nltk.download('averaged_perceptron_tagger')
# nltk.download('wordnet')
# nltk.download('omw-1.4')
# nltk.download('maxent_ne_chunker')
# nltk.download('words')
# nltk.download('punkt')

# # Hugging Face API setup
# API_URL = "https://api-inference.huggingface.co/models/pszemraj/flan-t5-large-grammar-synthesis"
# HEADERS = {"Authorization": f"Bearer {settings.HUGGING_FACE_API_KEY}"}  # Add token in settings

# # Helper functions
# def get_wordnet_pos(tag):
#     if tag.startswith('J'):
#         return wordnet.ADJ
#     elif tag.startswith('V'):
#         return wordnet.VERB
#     elif tag.startswith('N'):
#         return wordnet.NOUN
#     elif tag.startswith('R'):
#         return wordnet.ADV
#     return None

# def get_best_synonym(word, pos):
#     synonyms = []
#     for syn in wordnet.synsets(word, pos=pos):
#         for lemma in syn.lemmas():
#             synonym = lemma.name().replace('_', ' ')
#             if synonym.lower() != word.lower() and len(synonym.split()) == 1:
#                 synonyms.append((synonym, lemma.count()))
#     synonyms = sorted(synonyms, key=lambda x: x[1], reverse=True)
#     return random.choice([syn[0] for syn in synonyms[:3]]) if synonyms else word

# def extract_named_entities(text):
#     words = word_tokenize(text)
#     pos_tags = pos_tag(words)
#     named_entities = nltk.ne_chunk(pos_tags)
#     return {" ".join(c[0] for c in chunk) for chunk in named_entities if hasattr(chunk, 'label')}

# def paraphrase_sentence(sentence, preserved_terms):
#     corrected_sentence = str(TextBlob(sentence).correct())
#     named_entities = extract_named_entities(corrected_sentence)
#     words = word_tokenize(corrected_sentence)
#     paraphrased_sentence = []
#     for word, tag in pos_tag(words):
#         if word in preserved_terms or word in named_entities:
#             paraphrased_sentence.append(word)
#         else:
#             pos = get_wordnet_pos(tag)
#             paraphrased_sentence.append(get_best_synonym(word, pos) if pos else word)
#     return ' '.join(paraphrased_sentence)

# # API View
# class GenerateTextView(APIView):
#     RETRY_INTERVAL = 1  # Seconds between retries
#     MAX_RETRIES = 5  # Maximum number of retries

#     def post(self, request, *args, **kwargs):
#         preserved_terms = {"ERP", "AI", "machine learning", "deep learning", "data science", "enterprisingness", "imagination", "provision"}
#         text = request.data.get('text', '')

#         if not text:
#             return Response({"error": "Text is required."}, status=status.HTTP_400_BAD_REQUEST)

#         try:
#             # Step 1: Paraphrase the input text
#             paraphrased_text = paraphrase_sentence(text, preserved_terms)

#             # Step 2: Retry API call logic
#             api_response = self.retry_hugging_face_api({"inputs": paraphrased_text})

#             if "error" in api_response:
#                 raise APIException(f"API error: {api_response['error']}")

#             refined_text = api_response[0].get('generated_text', '')
#             return Response({
#                 "paraphrased_text": paraphrased_text,
#                 "generated_text": refined_text
#             })
#         except Exception as e:
#             return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#     def retry_hugging_face_api(self, payload):
#         """
#         Retry logic to handle model loading errors for Hugging Face API.
#         """
#         for attempt in range(self.MAX_RETRIES):
#             response = requests.post(API_URL, headers=HEADERS, json=payload)
#             api_response = response.json()

#             if response.status_code == 200 and "error" not in api_response:
#                 return api_response

#             # If the error indicates model is still loading, wait and retry
#             if "error" in api_response and "loading" in api_response["error"].lower():
#                 time.sleep(self.RETRY_INTERVAL)
#             else:
#                 # If it's a different error, stop retrying
#                 raise APIException(f"API error: {api_response.get('error', 'Unknown error')}")

#         # If max retries are exceeded
#         raise APIException("Max retries exceeded while waiting for the model to load.")

 
class GoogleLogin(SocialLoginView):  # For Authorization Code Grant
    adapter_class = GoogleOAuth2Adapter
    callback_url = "http://localhost:3000/"
    client_class = OAuth2Client

    def get_response(self):
        response = super().get_response()  # Get the default response
        user = self.user  # The logged-in user
        
        # Fetch the current plan from PlanPurchase or set plan_data to None
        current_plan = (
            PlanPurchase.objects.filter(user=user, Payment_Status=True,Expiry_Status=False)
            .order_by('-Purchase_Date')
            .first()
        )

        plan_data = (
            {
                "Plan_Name": current_plan.Plan_Name,
                "Expire_Date": current_plan.Expire_Date,
                "Expiry_Status":current_plan.Expiry_Status
            }
            if current_plan
            else None
        )

        # Add the plan data to the response
        response.data.update({"plan": plan_data})
        return response
# Create your views here.
class RegisterView(APIView):
    def post(self, request):
        username = request.data.get('username')
        email = request.data.get('email')
        password = request.data.get('password')

        # Check if the username or email already exists
        if User.objects.filter(username=username).exists():
            return Response({'error': 'Username already exists'}, status=status.HTTP_400_BAD_REQUEST)
        
        if User.objects.filter(email=email).exists():
            return Response({'error': 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Create the user
        user = User.objects.create_user(username=username, email=email, password=password)
        user.is_active = False  # Set user as inactive until OTP verification
        user.save()

        # Generate a random 6-digit OTP
        otp = random.randint(100000, 999999)
        
        # Save OTP in a temporary model (to be created)
        OTPVerification.objects.create(user=user, otp=otp, created_at=timezone.now())

        # Send OTP to the user's email
        send_mail(
            subject='Your OTP Verification Code',
            message=f'Your OTP code is {otp}. Please verify your account.',
            from_email='shoaib4311859@gmail.com',  # Replace with your sender email
            recipient_list=[email],
            fail_silently=False,
        )
        return Response({
            'status': 'Created',
            'user': {
                    'id':user.id,
                    'name':user.username,
                    'email':user.email,

                },
            'message': 'OTP sent to your email. Please verify your account.'
        }, status=status.HTTP_201_CREATED)

class RegisterVerifyOTPView(APIView):
    def post(self, request):
        user_id = request.data.get('user_id')
        otp = request.data.get('otp')

        try:
            otp_record = OTPVerification.objects.get(user_id=user_id, otp=otp)
        except OTPVerification.DoesNotExist:
            return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Check if OTP is expired (e.g., 10 minutes)
        if timezone.now() > otp_record.created_at + timezone.timedelta(minutes=10):
            return Response({'error': 'OTP expired'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Activate the user
        user = otp_record.user
        user.is_active = True
        user.save()

        # Delete OTP record after successful verification
        otp_record.delete()

        refresh = RefreshToken.for_user(user)

        return Response({
            'status': 'Verified',
            'user': {
                    'id':user.id,
                    'name':user.username,
                    'email':user.email,

                },
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        })

class LoginView(APIView):
    def post(self, request):
        identifier = request.data.get('identifier')
        password = request.data.get('password')
        user = None

        # Try to authenticate with email
        if '@' in identifier:
            try:
                user_obj = User.objects.get(email=identifier)
                user = authenticate(username=user_obj.username, password=password)
            except User.DoesNotExist:
                return Response({'error': 'Invalid email or password'}, status=status.HTTP_400_BAD_REQUEST)

        # Try to authenticate with username
        else:
            user = authenticate(username=identifier, password=password)
        current_plan = (
            PlanPurchase.objects.filter(user=user, Payment_Status=True,Expiry_Status=False)
            .order_by('-Purchase_Date')
            .first()
        )

        plan_data = (
            {
                "Plan_Name": current_plan.Plan_Name,
                "Expire_Date": current_plan.Expire_Date,
                "Expiry_Status":current_plan.Expiry_Status
            }
            if current_plan
            else None
        )


        if user is not None:
            refresh = RefreshToken.for_user(user)
            return Response({
                'status': 'Logged in',
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'plan': plan_data
                },
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)
class PlanExpiryHundler(APIView):
    def post(self, request):
        userpaln=PlanPurchase.objects.filter(user=request.user, Expire_Date=now()).update(Expiry_Status=True)
        if  userpaln:
             return Response({
                'message': 'Your Plan Have Been Expired!! Upgrade Again For Further Use',
            }, status=status.HTTP_200_OK)

        else:
            return Response({'message': 'User Plan Does Not Exist'}, status=status.HTTP_200_OK)

class ForgotPasswordView(APIView):
    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            try:
                user = User.objects.get(email=email)
                otp = str(random.randint(100000, 999999))
                OTPVerification.objects.create(user=user, otp=otp)

                # Send OTP via email
                send_mail(
                    'Your OTP Code',
                    f'Your OTP code is {otp}',
                    'your_email@example.com',
                    [email],
                    fail_silently=False,
                )
                return Response({'message': 'OTP sent to your email'}, status=status.HTTP_200_OK)
            except User.DoesNotExist:
                return Response({'error': 'User with this email does not exist'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Verify OTP View
class VerifyOTPView(APIView):
    def post(self, request):
        serializer = VerifyOTPSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp_code = serializer.validated_data['otp_code']

            try:
                otp = OTPVerification.objects.filter(user__email=email, otp=otp_code).latest('created_at')
                if otp.is_expired():
                    return Response({'error': 'OTP has expired'}, status=status.HTTP_400_BAD_REQUEST)

                # Delete OTP after successful verification
                
                return Response({'message': 'OTP verified successfully'}, status=status.HTTP_200_OK)

            except OTPVerification.DoesNotExist:
                return Response({'error': 'Invalid OTP or email'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Reset Password View
class PasswordResetView(APIView):
    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp_code = serializer.validated_data['otp_code']
            new_password = serializer.validated_data['new_password']

            try:
                otp = OTPVerification.objects.filter(user__email=email, otp=otp_code).latest('created_at')
                if otp.is_expired():
                    return Response({'error': 'OTP has expired'}, status=status.HTTP_400_BAD_REQUEST)

                user = otp.user
                user.set_password(new_password)
                user.save()

                # Delete OTP after successful password reset
                otp.delete()
                return Response({'message': 'Password reset successfully'}, status=status.HTTP_200_OK)

            except OTPVerification.DoesNotExist:
                return Response({'error': 'Invalid OTP or email'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        serializer = ChangePasswordSerializer(data=request.data, context={'request': request})

        if serializer.is_valid():
            # Set the new password
            user.set_password(serializer.validated_data['new_password'])
            user.save()

            return Response({"message": "Password updated successfully"}, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def check_plan_status(request):
    # Make sure the user is authenticated
    plan = PlanPurchase.objects.get(user=request.user) # Assuming the  latest plan is the active one
    if plan:
        current_date = now().date()
        is_expired = current_date > plan.Expire_Date
        message = "Your plan has expired. Please renew your subscription." if is_expired else "Your plan is active."
        
        return Response({
            "is_expired": is_expired,
            "message": message,
            "expire_date": plan.Expire_Date
        })
    else:
        return Response({
            "is_expired": True,
            "message": "You do not have an active plan. Please purchase a plan.",
            "expire_date": None
        })
@api_view(['GET'])
def get_all_plans(request):
    plans = Plan.objects.all()  # Fetch all plans
    
    # Convert the queryset to a list of dictionaries manually
    plans_data = [
        {
            'Plan_Name': plan.Plan_Name,
            'Price': plan.Price,
            'Duration': plan.Duration,
            'Discount': plan.Discount,
            'Benfit': plan.Benfit,
            'Created': plan.Created
        }
        for plan in plans
    ]
    
    # Return the list of dictionaries as a JSON response
    return Response(plans_data)

# class PlanDetail(APIView):
#     """
#     Retrieve a specific plan's details by its ID.
#     """
    
#     def get(self, request, plan_id):
#         try:
#             # Fetch a single plan by ID
#             plan = Plan.objects.get(id=plan_id)
            
#             # Serialize the single plan object
             
#             plans_data = [
#         {   'Plan_Id':plan.id,
#             'Plan_Name': plan.Plan_Name,
#             'Price': plan.Price,
#             'Duration': plan.Duration,
#             'Discount': plan.Discount,
#             'Benfit': plan.Benfit,
#             'Created': plan.Created
#         }
#             ]
    
            
#             # Return serialized data
#             return Response(plans_data, status=status.HTTP_200_OK)
        
#         except Plan.DoesNotExist:
#             # Plan not found, return 404
#             return Response({"error": "Plan not found"}, status=status.HTTP_404_NOT_FOUND)
        
#         except Exception as e:
#             # Catch any other exceptions and return the error message
#             return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

stripe.api_key =os.getenv("STRIPE_SECRETE")


@csrf_exempt
def create_payment_intent(request):

    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            amount = data.get('amount', 2000)  # Default to 2000 if not provided
            amount = float(20)  # Convert amount to float
            exchange_rate = 1.0  # Adjust if converting from another currency to USD
            usd_amount = amount * exchange_rate  # Convert to USD
            stripe_amount = int(usd_amount * 100)  # Convert to cents 
            intent = stripe.PaymentIntent.create(
                amount=stripe_amount,
                currency='usd',
                payment_method_types=['card'],
                capture_method='automatic',
                confirmation_method='automatic'
            )
             


            return JsonResponse({'clientSecret': intent.client_secret})
        except stripe.error.StripeError as e:
            return JsonResponse({'error': str(e)}, status=400)
    return JsonResponse({'error': 'Invalid request method'}, status=405)


@csrf_exempt
def verify_payment(request):
    if request.method == "POST":
        try:
            # Parse the request body
            data = json.loads(request.body)
            payment_intent_id = data.get("paymentIntentId")
            plan_name = data.get("plan_name")
            user_email = data.get("email")  # Assuming you send user_id from the frontend

            if not payment_intent_id or not plan_name or not user_email:
                return JsonResponse(
                    {"error": "PaymentIntent ID, plan name, and user Email are required"}, 
                    status=400
                )

            # Retrieve the PaymentIntent from Stripe
            payment_intent = stripe.PaymentIntent.retrieve(payment_intent_id)

            if payment_intent.status == "succeeded":
                # Retrieve the plan details
                from django.contrib.auth.models import User
                try:
                    user = User.objects.get(email=user_email)
                except User.DoesNotExist:
                    return JsonResponse({"error": "User not found"}, status=404)

                try:
                    plan = Plan.objects.get(Plan_Name=plan_name)
                except Plan.DoesNotExist:
                    return JsonResponse({"error": f"Plan '{plan_name}' not found"}, status=404)
                
                purchase_date = now()
                expiry_date = purchase_date + timedelta(days=float(plan.Duration))
                expiry_status = False if expiry_date > now() else True


                # Create a PlanPurchase record
                PlanPurchase.objects.create(
                    user=user,
                    Plan_Name=plan.Plan_Name,
                    Price=plan.Price,
                    Duration=plan.Duration,
                    Discount=plan.Discount,
                    Payment_Status=True,
                    Purchase_Date=now()
                )

                plan_details = {
                    "Plan_Name": plan.Plan_Name,
                    "Expire_Date": expiry_date,
                    "Expiry_Status": expiry_status
                }

                return JsonResponse({"success": True, "message": "Payment verified and plan updated.",'plan':plan_details})
            else:
                return JsonResponse({"error": "Payment not successful"}, status=400)
        except stripe.error.StripeError as e:
            return JsonResponse({"error": str(e)}, status=400)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)

    return JsonResponse({"error": "Invalid request method"}, status=405)    
# def paymentpage(request):
#     publickey= "pk_test_51QPJmpGGuOfO0EatCnS6Te6ZaSu1fCIJIQSwXr0kZKS7NH8xGVSLrZ7ZAsjvlTBGHqmiLCZ2LWV23bfSCs1PvOsu00vqmePYoQ"
#     return render(request,"payment.html",{'publickey':publickey})
# class PaypalPaymentView(APIView):
#     permission_classes = [permissions.IsAuthenticated]
#     """
#     Endpoint to create a payment URL
#     """
#     def post(self, request, *args, **kwargs):
#         amount = 20  # Example amount in USD
#         currency = "USD"
#         return_url = "https://example.com/payment/paypal/success/"
#         cancel_url = "https://example.com"

#         status, payment_id, approved_url = make_paypal_payment(amount, currency, return_url, cancel_url)
#         if status:
#             # Handle subscription and save payment ID (assuming plan is defined)
#             # handel_subscribtion_paypal(plan=plan, user_id=request.user, payment_id=payment_id)
#             return Response({
#                 "success": True,
#                 "msg": "Payment link has been successfully created",
#                 "approved_url": approved_url
#             }, status=201)
#         else:
#             return Response({
#                 "success": False,
#                 "msg": "Authentication or payment creation failed"
#             }, status=400)

# class PaypalValidatePaymentView(APIView):
#     """
#     Endpoint to validate PayPal payment
#     """
#     permission_classes = [permissions.IsAuthenticated]

#     def post(self, request, *args, **kwargs):
#         payment_id = request.data.get("payment_id")
#         if not payment_id:
#             return Response({
#                 "success": False,
#                 "msg": "Payment ID is required"
#             }, status=400)

#         payment_status = verify_paypal_payment(payment_id)
#         print(payment_id)
#         if payment_status:
#             # Handle successful payment logic here
#             return Response({
#                 "success": True,
#                 "msg": "Payment approved"
#             }, status=200)
#         else:
#             return Response({
#                 "success": False,
#                 "msg": "Payment failed or canceled"
#             }, status=400)
class GetProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Get the profile of the currently logged-in user
        profile = request.user.profile  # Assuming there is a OneToOne relationship between User and Profile
        serializer = GetProfileSerializer(profile)
        
        return Response(serializer.data, status=status.HTTP_200_OK)

class ProfileUpdateView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def get(self, request):
        try:
            profile = Profile.objects.get(user=request.user)
            serializer = ProfileSerializer(profile)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Profile.DoesNotExist:
            return Response({"error": "Profile not found"}, status=status.HTTP_404_NOT_FOUND)

    def put(self, request):
        try:
            profile = Profile.objects.get(user=request.user)
            serializer = ProfileSerializer(profile, data=request.data, partial=True)

            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Profile.DoesNotExist:
            return Response({"error": "Profile not found"}, status=status.HTTP_404_NOT_FOUND)


class ContactUsView(APIView):
    def post(self, request):
        serializer = ContactSerializer(data=request.data)
        
        if serializer.is_valid():
            contact = serializer.save()

            # Sending email to admin
            subject = f"New Contact Us Message: {contact.subject}"
            message = f"From: {contact.name} <{contact.email}>\n\n{contact.message}"
            admin_email = settings.EMAIL_HOST_USER  # Set this in your settings.py

            send_mail(subject, message, contact.email, [admin_email])

            return Response({'message': 'Thank you for contacting us!'}, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
 
class HixAPIHandler(APIView):
    #permission_classes = [IsAuthenticated]
    def post(self, request):
        # Get URLs and API key from environment variables
        submit_url = os.getenv("SUBMIT_URL")
        obtain_url = os.getenv("OBTAIN_URL")
        api_key = os.getenv("API_KEY")

        # Extract input data from request
        payload = {
            "input": request.data.get("text"),
            "mode": request.data.get("mode", "Aggressive")
        }
        headers = {"api-key": api_key}

        try:
            # Step 1: Send data to 'submit' API
            submit_response = requests.post(submit_url, json=payload, headers=headers)
            submit_response_data = submit_response.json()

            if submit_response_data.get("err_code") != 0:
                return Response(
                    {"error": "Failed to submit data", "details": submit_response_data},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Extract task_id from submit response
            task_id = submit_response_data["data"]["task_id"]

            # Step 2: Poll the 'obtain' API until task completes
            max_retries = 100  # Maximum number of retries
            retry_interval = 7 # Time (in seconds) between retries

            for _ in range(max_retries):
                obtain_response = requests.get(f"{obtain_url}?task_id={task_id}", headers=headers)
                obtain_response_data = obtain_response.json()

                # Check if the task is complete
                if obtain_response_data.get("data", {}).get("subtask_status") == "completed":
                    # Combine the responses and return
                    combined_data = {
                        #"submit_response": submit_response_data,
                        #"obtain_response": obtain_response_data,
                        "generated_text":obtain_response_data['data']['output']
                    }
                    return Response(combined_data, status=status.HTTP_200_OK)

                # If the task is still running, wait before retrying
                time.sleep(retry_interval)

            # If task did not complete after retries, return an error
            return Response(
                {"error": "Task did not complete within the allowed time", "details": obtain_response_data},
                status=status.HTTP_408_REQUEST_TIMEOUT
            )

        except Exception as e:
            return Response(
                {"error": "An error occurred", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
 


@api_view(['POST'])
# permission_classes([IsAuthenticated])
def ai_detector(request):
    # API_URL = "https://api-inference.huggingface.co/models/TrustSafeAI/RADAR-Vicuna-7B"
    # headers = {"Authorization": os.getenv("KEY")} 

    # def query(payload):
    #     response = requests.post(API_URL, headers=headers, json=payload)
    #     return response.json()
    user_text=request.data['text']

    # user_text = request.data.get("inputs",  text)
    # result = query({"inputs": user_text})
    # score = result[:1][0]
    # human_score=score[0]["score"]
    # ai_score=score[1]["score"]
    # label="Nutural"
    # if ai_score>=0.60:
    #     label="AI Generated:High Confidence"
    # if human_score>=0.60:
    #     label="Human:High Confidence"
    from gradio_client import Client

    client = Client("jinyin3/RADAR-AI-Text-Detector")
    result = client.predict(
		text= user_text,
		api_name="/predict"
)
    print(result)
    
    if result:
        return Response(result, status=status.HTTP_200_OK)
    else:
        return Response("Sorry Something Went Wrong!!", status=status.HTTP_400_BAD_REQUEST)

 

