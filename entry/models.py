from django.db import models


class ContactForm(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    message = models.TextField()
    reply_sent = models.BooleanField(default=False)
    reply_message = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"Message from {self.name}"