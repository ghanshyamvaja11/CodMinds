from django.db import models

class InternshipProjects(models.Model):
    field = models.CharField(max_length=255)
    title = models.CharField(max_length=255)
    description = models.CharField(max_length=1200)
    duration = models.IntegerField()

    def __str__(self):
        return f"Project for {self.recipient_name}"

    @staticmethod
    def get_unique_fields():
        return InternshipProjects.objects.values_list('field', flat=True).distinct()

class AllottedProject(models.Model):
    project_id = models.IntegerField()
    email = models.EmailField()
    start_date = models.DateField(auto_now_add=True)
    end_date = models.DateField()
