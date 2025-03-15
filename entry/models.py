from django.db import models


class ContactForm(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    subject = models.CharField(max_length=100, null=True)
    message = models.TextField()
    reply_sent = models.BooleanField(default=False)
    reply_message = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"Message from {self.name}"


class HireUs(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    hiring_details = models.TextField()
    message = models.TextField(null=True, blank=True)
    reply_sent = models.BooleanField(default=False)

    def __str__(self):
        return f"Message from {self.name}"

class Subscribe(models.Model):
    email = models.EmailField(primary_key=True)

    def __str__(self):
        return f"email: {self.email}"