from django.db import models
from authority.models import *

class User(models.Model):
    name = models.CharField(max_length=255, unique=True)
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=15)
    password = models.CharField(max_length=255)

    def __str__(self):
        return self.username


class InternshipApplication(models.Model):
    DEPARTMENT_CHOICES = [
        ('web-development', 'Web Development'),
        ('data-science', 'Data Science'),
        ('cyber-security', 'Cyber Security'),
        ('ai-ml', 'AI & Machine Learning'),
    ]

    name = models.CharField(max_length=100)
    email = models.EmailField()
    phone = models.CharField(max_length=15)
    department = models.CharField(max_length=50, choices=DEPARTMENT_CHOICES)
    cover_letter = models.TextField(blank=True, null=True)
    resume = models.FileField(upload_to='resumes/')
    project_name = models.CharField(max_length=240, null=True)
    project_description = models.CharField(max_length=1200, null=True)
    status=models.IntegerField(default=-1)
    offer_letter = models.BooleanField(default=False)
    submitted_at = models.DateField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} - {self.department}"


class Payment(models.Model):
    order_id = models.CharField(max_length=255)
    payment_id = models.CharField(max_length=50)
    signature = models.CharField(max_length=256, null=True, blank=True)
    refund_payment_id = models.CharField(max_length=255)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    refund_amount = models.DecimalField(max_digits=10, decimal_places=2, null=True)
    email = models.EmailField()  # Added field to store the user's email
    project_id = models.IntegerField(null=True)
    status = models.CharField(max_length=100, choices=[(
        'Pending', 'Pending'), ('Completed', 'Completed'), ('Failed', 'Failed')], default='Pending')

    def __str__(self):
        return f"Payment - {self.order_id} for {self.email}"