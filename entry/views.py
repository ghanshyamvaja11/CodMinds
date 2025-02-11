from django.shortcuts import render
from .models import *
from django.contrib import messages
from django.contrib.messages import get_messages

def clear_messages(request):
    storage = get_messages(request)
    for _ in storage:
        pass

def home(request):
    clear_messages(request)
    return render(request, 'index.html')

def about(request):
    clear_messages(request)
    return render(request, 'aboutus.html')

def services(request):
    clear_messages(request)
    return render(request, 'services.html')

def T_and_C(request):
    clear_messages(request)
    return render(request, 'T&C.html')  

def privacy_policy(request):
    clear_messages(request)
    return render(request, 'privacy_policy.html')

def cancellation_refund_policies(request):
    clear_messages(request)
    return render(request, 'cancellation_refund_policies.html')
    
def contact(request):
    clear_messages(request)
    if request.method == 'POST':
        # Get form data
        name = request.POST.get('name')
        email = request.POST.get('email')
        subject = request.POST.get('subject')
        message = request.POST.get('message')

        # Save data to database
        contact_message = ContactForm(name=name, email=email, subject=subject, message=message)
        contact_message.save()

        # Success message
        messages.success(request, "Thank you for your message. We will get back to you soon.")
        return render(request, 'index.html')
    return render(request, 'contactus.html')

def error_404_view(request, exception=None):
    clear_messages(request)
    return render(request, '404.html', status=404)
