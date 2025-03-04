from django.shortcuts import render, redirect
from .models import *
from django.contrib import messages
from django.contrib.messages import get_messages
from authority.models import InternshipProjects
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from carriers.models import *

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
        contact_message = ContactForm(
            name=name, email=email, subject=subject, message=message)
        contact_message.save()

        # Success message
        messages.success(
            request, "Thank you for your message. We will get back to you soon.")
        return render(request, 'index.html')
    return render(request, 'contactus.html')


def internship_program(request):
    clear_messages(request)
    query = request.GET.get('search', '')
    field = request.GET.get('field', '')
    duration = request.GET.get('duration', '')

    internships = InternshipProjects.objects.all()

    if query:
        internships = internships.filter(title__icontains=query)
    if field:
        internships = internships.filter(field=field)
    if duration:
        internships = internships.filter(duration=duration)

    fields = InternshipProjects.get_unique_fields()

    return render(request, 'internship_program.html', {
        'internships': internships,
        'query': query,
        'field': field,
        'duration': duration,
        'fields': fields,
        'selected_field': field,
    })


def web_development(request):
    clear_messages(request)
    return render(request, 'web_development.html')


def software_development(request):
    clear_messages(request)
    return render(request, 'software_development.html')


def data_analytics(request):
    clear_messages(request)
    return render(request, 'data_analytics.html')


def error_404_view(request, exception=None):
    clear_messages(request)
    return render(request, '404.html', status=404)


def hire_us(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        email = request.POST.get('email')
        hiring_details = request.POST.get('details')

        # Save data to database
        hire_us_message = HireUs(
            name=name, email=email, hiring_details=hiring_details)
        hire_us_message.save()

        # Send email
        send_mail(
            subject=f"Hire Us Request sent",
            message=f"Name: {name}\nEmail: {email}\n\nHiring Details:\n{hiring_details} \nThank you for your request. We will get back to you soon.",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
        )

        messages.success(
            request, "Thank you for your request. We will get back to you soon.")
        return redirect(request.META.get('HTTP_REFERER', '/'))
    return redirect('home')


def carrier(request):
    clear_messages(request)
    try:
        if request.session.get('email'):
            user_email = request.session.get('email')
            vacancies = Vacancy.objects.filter(
                is_active=True, last_date_of_application__gte=timezone.now().date()
            ).order_by('-posted_date')

            applied_jobs = JobApplication.objects.filter(
                applicant_email=user_email).values_list('vacancy_id', flat=True)

            return render(request, 'carrier.html', {'vacancies': vacancies, 'applied_jobs': applied_jobs})
        else:
            vacancies = Vacancy.objects.filter(
                is_active=True, last_date_of_application__gte=timezone.now().date()
            ).order_by('-posted_date')

            return render(request, 'carrier.html', {'vacancies': vacancies, 'applied_jobs': []})
    except Exception as e:
        messages.error(
            request, "An unexpected error occurred. Please try again.")
        return render(request, 'carrier.html', {'vacancies': [], 'applied_jobs': []})
