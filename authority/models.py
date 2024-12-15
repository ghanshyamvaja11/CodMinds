from django.db import models


class InternshipProjects(models.Model):
    field = models.CharField(max_length=255)
    title = models.CharField(max_length=255)
    description = models.CharField(max_length=1200)

    def __str__(self):
        return f"Certificate for {self.recipient_name}"