from django.db import models
from django.utils import timezone

class InternshipCertificate(models.Model):
    recipient_name = models.CharField(max_length=255)
    email = models.EmailField(max_length=254)
    phone = models.CharField(max_length=15)
    internship_field = models.CharField(max_length=255)
    project = models.CharField(max_length=255)
    start_date = models.DateField()
    end_date = models.DateField()
    issued_at = models.DateField(auto_now_add=True)
    certificate_code = models.CharField(max_length=10)
    certficate = models.FileField(upload_to='certificates/', null=True)


    def __str__(self):
        return f"Certificate for {self.recipient_name}"


# class TrainingCertificate(models.Model):
#     recipient_name = models.CharField(max_length=255)
#     email = models.EmailField(max_length=254)
#     mobile_no = models.CharField(max_length=15)
#     field = models.CharField(max_length=255)
#     start_date = models.DateField()
#     end_date = models.DateField()
#     certificate_code = models.CharField(max_length=10)
#     issued_at = models.DateTimeField(auto_now_add=True)

#     def __str__(self):
#         return f"Certificate for {self.recipient_name}"
