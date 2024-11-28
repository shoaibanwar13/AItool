
from rest_framework import serializers
from .models import *
from django.contrib.auth.password_validation import validate_password
from rest_framework.exceptions import ValidationError
from rest_framework import serializers

class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

class PasswordResetConfirmSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(min_length=8)
class PlanSerializer(serializers.Serializer):
    class Meta:
        model=Plan
        fields = ['Plan_Name', 'Price', 'Duration', 'Discount', 'Benfit', 'Created']
class PlanStatusSerializer(serializers.Serializer):
    is_expired=serializers.BooleanField()
    message=serializers.CharField()
    is_expired=serializers.DateField()
class PlanDetailSerializer(serializers.Serializer):
    model=Plan
    fields=['Plan_Name', 'Price', 'Duration', 'Discount', 'Benfit', 'Created']



# Serializer for Forgot Password
class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

# Serializer for OTP Verification
class VerifyOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp_code = serializers.CharField(max_length=6)

# Serializer for Reset Password
class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp_code = serializers.CharField(max_length=6)
    new_password = serializers.CharField(write_only=True)

    def validate_new_password(self, value):
        from django.contrib.auth.password_validation import validate_password
        try:
            validate_password(value)
        except ValidationError as e:
            raise serializers.ValidationError(e.messages)
        return value

# Forgot Password View

class ChangePasswordSerializer(serializers.Serializer):
    current_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True, validators=[validate_password])

    def validate_current_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Current password is incorrect")
        return value

    def validate_new_password(self, value):
        validate_password(value)
        return value
class GetProfileSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(source='user.first_name', read_only=True)
    last_name = serializers.CharField(source='user.last_name', read_only=True)
    last_login=serializers.CharField(source='user.last_login', read_only=True)
    class Meta:
        model = Profile
        fields = ['first_name', 'last_name', 'last_login','country', 'profile_pic']

class ProfileSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(source='user.first_name', required=False)
    last_name = serializers.CharField(source='user.last_name', required=False)

    class Meta:
        model = Profile
        fields = ['first_name', 'last_name','country', 'profile_pic']  # Add fields as needed

    def update(self, instance, validated_data):
        # Update the user fields first
        user_data = validated_data.pop('user', {})
        user = instance.user

        user.first_name = user_data.get('first_name', user.first_name)
        user.last_name = user_data.get('last_name', user.last_name)
        user.save()

        # Update the profile fields
        instance.profile_pic = validated_data.get('profile_pic', instance.profile_pic)
        instance.country=validated_data.get('country', instance.country)
        instance.save()

        return instance

class TextInputSerializer(serializers.Serializer):
    text = serializers.CharField()

class ContactSerializer(serializers.ModelSerializer):
    class Meta:
        model = Contact
        fields = ['name', 'email', 'subject', 'message']
  

class PlanPurchaseSerializer(serializers.ModelSerializer):
    class Meta:
        model = PlanPurchase
        fields = '__all__'
       