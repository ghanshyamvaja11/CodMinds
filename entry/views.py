from django.shortcuts import render
from .models import *

def home(request):
    return render(request, 'index.html')

def about(request):
    return render(request, 'aboutus.html')

def services(request):
    return render(request, 'services.html')

def T_and_C(request):
    return render(request, 'T&C.html')  

def privacy_policy(request):
    return render(request, 'privacy_policy.html')

def cancellation_refund_policies(request):
    return render(request, 'cancellation_refund_policies.html')
    
def contact(request):
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
        success = "Thank you for your message. We will get back to you soon."
        return render(request, 'index.html', {'success': success})
    return render(request, 'contactus.html')

def error_404_view(request, exception=None):
    return render(request, '404.html', status=404)
