from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    profile_pic = models.ImageField(upload_to='profile_pics/', default='default.jpg')  # Default profile picture
    country=models.CharField(max_length=100,null=True,blank=True) 

    def __str__(self):
        return self.user.username


class OTPVerification(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)  # Links the OTP to the user
    otp = models.CharField(max_length=6)  # Stores the OTP as a 6-digit code
    created_at = models.DateTimeField(auto_now_add=True)  # Records when the OTP was created

    def __str__(self):
        return f"OTP for {self.user.username}: {self.otp}"

    def is_expired(self):
        """
        Returns True if the OTP is expired, else False.
        You can adjust the expiration time by modifying the timedelta.
        """
        return timezone.now() > self.created_at + timezone.timedelta(minutes=10)
class Plan(models.Model):
    Plan_Name=models.CharField(max_length=200)
    Price=models.DecimalField(max_digits=6,decimal_places=2)
    Duration=models.DecimalField(max_digits=4,decimal_places=2)
    Discount=models.DecimalField(max_digits=4,decimal_places=2)
    Benfit=models.DecimalField(max_digits=6,decimal_places=2)
    Created=models.DateTimeField(auto_now=True)
    def __str__(self):
        return f"{self.Plan_Name}"
class PlanPurchase(models.Model):
    user=models.ForeignKey(User,related_name="Purchased",on_delete=models.CASCADE)
    Plan_Name=models.CharField(max_length=200)
    Price=models.DecimalField(max_digits=6,decimal_places=2)
    Payment_Status=models.BooleanField(default=False)
    Duration=models.DecimalField(max_digits=4,decimal_places=2)
    Discount=models.DecimalField(max_digits=4,decimal_places=2)
    Expire_Date=models.DateField()
    Purchase_Date=models.DateTimeField(auto_now=True)
    Expiry_Status=models.BooleanField(default=False)
    def __str__(self):
        return f"{self.Plan_Name}"
    def save(self,*args,**kwargs):
        #calculate Expiry date 
        if not self.Expire_Date:
            self.Expire_Date=(self.Purchase_Date+timedelta(days=float(self.Duration))).date(
            )
        super().save(*args,**kwargs)
class Contact(models.Model):
    name = models.CharField(max_length=255)
    email = models.EmailField()
    subject = models.CharField(max_length=255)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Message from {self.name} - {self.email}"