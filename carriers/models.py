from django.db import models
from django.utils import timezone

# Create your models here.


class Vacancy(models.Model):
    title = models.CharField(max_length=255)
    description = models.TextField()
    location = models.CharField(max_length=255)
    posted_date = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    last_date_of_application = models.DateField()

    def __str__(self):
        return self.title

    def save(self, *args, **kwargs):
        if self.last_date_of_application < timezone.now().date():
            self.is_active = False
        super().save(*args, **kwargs)


class JobApplication(models.Model):
    vacancy = models.ForeignKey(Vacancy, on_delete=models.CASCADE)
    applicant_name = models.CharField(max_length=255)
    applicant_email = models.EmailField()
    resume = models.FileField(upload_to='resumes/')
    cover_letter = models.TextField()
    status = models.CharField(max_length=255, default='Submitted')
    selection_round = models.CharField(max_length=255, null=True)
    applied_date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.applicant_name} - {self.vacancy.title}"
