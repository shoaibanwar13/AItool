from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import User
from .models import Profile
import random
import string
from django.contrib.auth.models import User
from django.db import transaction
from django.db.models.signals import pre_save
from django.dispatch import receiver
import random
import string

# In your_app/signals.py
from django.contrib.auth.signals import user_logged_in
from django.dispatch import receiver
from django.contrib.auth.models import User

@receiver(user_logged_in)
def set_username_on_google_login(sender, request, user, **kwargs):
    # Ensure the user doesn't already have a username
    if not user.username:
        # Fetch the username from social account details
        social_account = user.socialaccount_set.first()  # Assuming you're using django-allauth
        if social_account:
            username =social_account.extra_data.get('email', '').split('@')[0]
            user.username = username
            user.save()

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    instance.profile.save()
