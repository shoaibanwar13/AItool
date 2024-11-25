from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import User
from .models import Profile
import random
import string
from django.contrib.auth.models import User
from django.db.models.signals import pre_save
from django.dispatch import receiver

def generate_unique_username():
    """Generate a random, unique username."""
    while True:
        username = 'user_' + ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        if not User.objects.filter(username=username).exists():
            return username

@receiver(pre_save, sender=User)
def set_unique_username(sender, instance, **kwargs):
    """Set a unique username if not provided."""
    if not instance.username:
        instance.username = generate_unique_username()


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    instance.profile.save()
