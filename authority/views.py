import random
from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from django.core.exceptions import ObjectDoesNotExist
from user.models import InternshipApplication
from django.shortcuts import get_object_or_404, redirect
from django.core.mail import send_mail
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login
from django.contrib import messages
from django.core.mail import EmailMessage
from django.http import HttpResponse, JsonResponse,  HttpResponseRedirect
from django.template.loader import get_template, render_to_string
from xhtml2pdf import pisa  # Install this library for PDF generation
from io import BytesIO
from certificate.models import *
from random import *
from django.views.decorators.csrf import csrf_exempt
import os
from datetime import datetime
from django.utils.timezone import make_aware
from django.conf import settings
from django.core.files.base import ContentFile
from django.contrib.auth import logout
from .models import *
from user.models import *
from entry.models import *
from django.core.files.storage import FileSystemStorage
from django.contrib.auth.models import User as Admin
import random

def admin_login(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        # Authenticate user
        user = authenticate(request, username=username, password=password)
        if user is not None and user.is_staff:  # Ensure user is an admin
            login(request, user)
            return redirect("admin_dashboard")
        else:
            return render(request, "admin_login.html", {"error_message": "Invalid username or password."})
    return render(request, "admin_login.html")


def admin_dashboard(request):
    return render(request, 'admin_dashboard.html')


def admin_logout(request):
    # Handle both GET and POST methods
    if request.method in ['POST', 'GET']:
        logout(request)  # Log out the user
        # Ensure 'admin_login' is a valid URL name
        return redirect('admin_login')
    else:
        # If the method is neither GET nor POST, fallback to the login page
        return redirect('admin_login')

# Forgot Password View


def forgot_password(request):
    if request.method == "POST":
        email = request.POST.get('email')

        # Check if email exists in the database
        try:
            # Ensure it's an admin user
            user = Admin.objects.get(email=email, is_staff=True)
        except Admin.DoesNotExist:
            messages.error(request, "Email not found or not an admin account.")
            return redirect('admin_forgot_password')

        # Store email in session for later use
        request.session['email'] = email

        # Generate OTP and send it via email
        otp = random.randint(100000, 999999)
        request.session['otp'] = otp  # Store OTP in session for verification
        send_mail(
            'Your OTP for Password Reset',
            f'Your OTP code is: {otp}',
            'your_email@example.com',
            [email],
            fail_silently=False,
        )

        # Redirect to OTP verification page
        return redirect('admin_verify_otp')

    return render(request, 'admin_forgot_password.html')

# OTP Verification View


def verify_otp(request):
    if request.method == "POST":
        otp_entered = request.POST.get('otp')

        if str(request.session.get('otp')) == otp_entered:
            # Redirect to password reset page
            return redirect('admin_reset_password')
        else:
            messages.error(request, "Invalid OTP. Please try again.")
            # Stay on OTP verification page
            return render(request, 'admin_verify_otp.html')

    return render(request, 'admin_verify_otp.html')

# Password Reset View


def reset_password(request):
    if request.method == "POST":
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        if password == confirm_password:
            email = request.session.get('email')  # Get email from session
            try:
                # Ensure it's an admin user
                user = Admin.objects.get(email=email, is_staff=True)
            except Admin.DoesNotExist:
                messages.error(request, "Admin not found.")
                return redirect('admin_forgot_password')

            # Use set_password to hash the password
            user.set_password(password)
            user.save()
            messages.success(request, "Password successfully reset!")
            # Redirect to login after resetting password
            return redirect('admin_login')
        else:
            messages.error(request, "Passwords do not match.")
            # Stay on reset password page
            return render(request, 'admin_reset_password.html')

    return render(request, 'admin_reset_password.html')


def add_internship_project(request):
    if request.method == 'POST':
        # Extract form data from POST request
        field = request.POST.get('field')
        title = request.POST.get('title')
        description = request.POST.get('description')

        # Create and save new internship project
        project = InternshipProjects(
            field=field,
            title=title,
            description=description
        )
        project.save()

        # Optionally display a success message
        success_message = "Internship project added successfully!"

        return render(request, 'add_internship_project.html', {'success': success_message})

    return render(request, 'add_internship_project.html')


def view_internship_applications(request):
    applications = InternshipApplication.objects.all()
    return render(request, 'view_internship_applications.html', {'applications': applications})

# Approve or Reject Internship Application


def approve_or_reject_application(request, app_id):
    # Fetch the internship application by ID
    application = get_object_or_404(InternshipApplication, id=app_id)

    if request.method == 'POST':
        status = request.POST.get('status')

        if status == 'approved':
            application.status = 1  # Mark the status as approved
            # Send email to the user if selected
            send_mail(
                'Internship Application Status: Approved',
                f'Congratulations! Your application for the internship has been approved. Please log in to your dashboard and select a project of your choice.',
                settings.DEFAULT_FROM_EMAIL,
                [application.email],
                fail_silently=False,
            )
        elif status == 'rejected':
            application.status = 0  # Mark the status as rejected
            # Send email to the user if rejected
            send_mail(
                'Internship Application Status: Rejected',
                f'We regret to inform you that your application for the internship has been rejected. Thank you for your interest.',
                settings.DEFAULT_FROM_EMAIL,
                [application.email],
                fail_silently=False,
            )

        application.save()  # Save the changes to the database

        # Redirect to the applications list page after updating the status
        return redirect('view_internship_applications')

    # If not a POST request, redirect back to the application list
    return redirect('view_internship_applications')

# # Update Project Allocation for Approved Applicants


def update_project_allocation(request, app_id):
    # Fetch the internship application by ID
    application = get_object_or_404(InternshipApplication, id=app_id)

    if request.method == 'POST':
        # Only update project details if the applicant is approved
        if application.status == 1:
            project_name = request.POST.get('project_name')
            project_description = request.POST.get('project_description')

            # Update the project details
            application.project_name = project_name
            application.project_description = project_description
            application.save()

            messages.success(request, "Project details updated successfully.")
        else:
            messages.error(request, "This application is not approved yet.")

        return redirect('view_internship_applications')

    return redirect('view_internship_applications')

# Issue Certificate


def eligible_users(request):
    users = InternshipApplication.objects.filter(status=1)
    return render(request, 'eligible_for_certificate.html', {'users': users})


def issue_certificate(request):
    user = None
    internship = None
    email = request.GET.get('email')

    # Handle GET request
    if request.method == "GET":
        user = User.objects.get(email=email)
        internship = InternshipApplication.objects.get(email=email)

    # Handle POST request
    if request.method == "POST":
        # Collect form data
        certificate_type = request.POST.get("certificate_type")
        recipient_name = request.POST.get("recipient_name")
        email = request.POST.get("email")
        mobile_no = request.POST.get("mobile_no")
        field = request.POST.get("field")
        project = request.POST.get("project")
        start_date = request.POST.get("start_date")
        end_date = request.POST.get("end_date")
        certificate_code = "INTERN-" + \
            str(InternshipCertificate.objects.count() + randint(100000, 999999))

        # Create certificate object
        if certificate_type == "internship":
            certificate = InternshipCertificate.objects.create(
                recipient_name=recipient_name,
                email=email,
                phone=mobile_no,
                internship_field=field,
                project=project,
                start_date=start_date,
                end_date=end_date,
                certificate_code=certificate_code,
            )
        else:
            certificate = TrainingCertificate.objects.create(
                recipient_name=recipient_name,
                email=email,
                phone=mobile_no,
                training_field=field,
                start_date=start_date,
                end_date=end_date,
                certificate_code=certificate_code,
            )

        request.session['email'] = email

        # Email body with verification link
        email_body = f"""
        Dear {recipient_name},

        Congratulations on successfully completing your {certificate_type}!

        It will be visible in the certificates section of your dashboard and will also be sent to your email.

        You can verify your certificate using the following link:
        http://codminds.pythonanywhere.com/certificate/{certificate_type}/verify/{certificate_code}

        Best regards,
        CodMinds Team
        """

        # Prepare and send the email
        email_message = EmailMessage(
            subject=f"Your {certificate_type.capitalize()} Certificate",
            body=email_body,
            from_email="codmindsofficial@gmail.com",
            to=[email],
        )
        email_message.send()

        # Fetch the created certificate for rendering
        certificate = InternshipCertificate.objects.get(
            certificate_code=certificate_code)

        success = "Certificate issued and emailed successfully!"
        context = {
            'recipient_name': certificate.recipient_name,
            'internship_field': certificate.internship_field,
            'project_name': certificate.project,
            'start_date': certificate.start_date,
            'end_date': certificate.end_date,
            'issued_at': certificate.issued_at,
            'certificate_code': certificate.certificate_code,
            'success': success,
        }

        return render(request, 'print_intern_certificate.html', context)

    return render(request, "issue_certificate.html", {'user': user, 'internship': internship})


# upload Internship certificate
def eligible_interns_for_certificate(request):
    users = InternshipApplication.objects.filter(status=1)
    return render(request, 'eligible_for_internship_certificate.html', {'users': users})


def upload_internship_certificate(request):
    email = request.session.get('email')

    # Check if email is provided in the GET request, else use session
    if request.method == 'GET' and request.GET.get('email') != '':
        email = request.GET.get('email')

    # Handle the file upload when POST request is made
    if request.method == 'POST' and request.FILES.get('certificate_file'):
        certificate_file = request.FILES['certificate_file']

        # Ensure email is valid
        if not email:
            messages.error(request, 'Email is required.')
            return redirect('internship_certificate_upload')

        # Get the internship certificate object based on the email
        internship_certificate = InternshipCertificate.objects.filter(
            email=email).first()

        if internship_certificate:
            # Check if the uploaded file is valid
            if certificate_file.size > 0:
                original_filename = certificate_file.name  # Keep original filename

                # Save the file to the media/certificates directory
                fs = FileSystemStorage(location=os.path.join(
                    settings.MEDIA_ROOT, 'certificates'))
                try:
                    # Save with the original filename
                    filename = fs.save(original_filename, certificate_file)
                    # Get the URL of the uploaded file
                    file_url = fs.url(filename)

                    # Update the certificate URL in the database
                    internship_certificate.certficate = file_url
                    internship_certificate.save()

                    # Send the certificate via email
                    email_subject = 'Your Internship Certificate'
                    email_body = f"Dear {internship_certificate.email},\n\nPlease find your internship certificate attached.\n\nBest regards,\nCodMinds"
                    email_message = EmailMessage(
                        email_subject,
                        email_body,
                        settings.DEFAULT_FROM_EMAIL,  # Use default email from settings.py
                        [internship_certificate.email],  # Send to user's email
                    )
                    # Attach the uploaded certificate file to the email
                    email_message.attach_file(os.path.join(
                        settings.MEDIA_ROOT, 'certificates', original_filename))

                    # Send the email
                    email_message.send()

                    # Display success message
                    messages.success(
                        request, 'Certificate uploaded and emailed successfully!')
                except Exception as e:
                    # Handle errors during file save or email send
                    messages.error(
                        request, f"File upload or email send failed: {str(e)}")
            else:
                messages.error(
                    request, 'File is empty. Please upload a valid file.')
        else:
            messages.error(
                request, 'Internship certificate not found for the provided email.')

        # Redirect back to the same page after the upload
        return redirect('internship_certificate_upload')

    return render(request, 'internship_certificate_upload.html')


def generate_internship_certificate(request, certificate_code):
    certificate = InternshipCertificate.objects.get(
        certificate_code=certificate_code)

    context = {
        'recipient_name': certificate.recipient_name,
        'internship_field': certificate.internship_field,
        'project_name': certificate.project,
        'start_date': certificate.start_date,
        'end_date': certificate.end_date,
        'issued_at': certificate.issued_at,
        'certificate_code': certificate.certificate_code,
    }

    return render(request, 'print_intern_certificate.html', context)


def issued_internship_certificates(request):
    # Fetch all issued certificates from the database
    issued_certificates = InternshipCertificate.objects.all()

    # Render the template with the context data
    context = {
        'issued_certificates': issued_certificates
    }
    return render(request, 'issued_internship_certificates.html', context)

def contact_us(request):
    """View to display all contact queries."""
    queries = ContactForm.objects.all()
    return render(request, 'contactus_reply.html', {'queries': queries})


def contact_us_reply(request, query_id):
    """View to handle replying to a specific contact query."""
    query = get_object_or_404(ContactForm, id=query_id)

    if request.method == 'POST':
        reply_message = request.POST.get('reply_message')

        if not reply_message:
            messages.error(request, "Reply message cannot be empty.")
            return redirect('contact_us_view')

        # Save the reply and mark the query as replied
        query.reply_message = reply_message
        query.reply_sent = True
        query.save()

        # Sending an email with the reply
        try:
            send_mail(
                subject=f"Reply to your query on CodMinds",
                message=f"Dear {query.name},\n\nThank you for reaching out to us. Here is our reply to your query:\n\n{reply_message}\n\nBest regards,\nCodMinds Team",
                from_email='support@codminds.com',
                recipient_list=[query.email],
                fail_silently=False,
            )
            messages.success(
                request, f"Reply sent successfully to {query.name}.")
        except Exception as e:
            messages.error(request, f"Failed to send email. Error: {str(e)}")

        return redirect('contact_us_view')

    return render(request, 'contactus_reply.html', {'query': query})


# def issue_certificate(request):
#     if request.method == "POST":
#         # Collect form data
#         certificate_type = request.POST["certificate_type"]
#         recipient_name = request.POST["recipient_name"]
#         email = request.POST["email"]
#         mobile_no = request.POST["mobile_no"]
#         field = request.POST["field"]
#         project = request.POST["project"]
#         start_date = request.POST["start_date"]
#         end_date = request.POST["end_date"]
#         certificate_code = "INTERN-" + str(
#             InternshipCertificate.objects.count() + randint(100000, 999999)
#         )

#         # Create certificate object
#         if certificate_type == "internship":
#             certificate = InternshipCertificate.objects.create(
#                 recipient_name=recipient_name,
#                 email=email,
#                 mobile_no=mobile_no,
#                 internship_field=field,
#                 project=project,
#                 start_date=start_date,
#                 end_date=end_date,
#                 certificate_code=certificate_code,
#             )
#         else:
#             certificate = TrainingCertificate.objects.create(
#                 recipient_name=recipient_name,
#                 email=email,
#                 mobile_no=mobile_no,
#                 training_field=field,
#                 start_date=start_date,
#                 end_date=end_date,
#                 certificate_code=certificate_code,
#             )

#         # Render HTML content
#         html_content = render_to_string("print_intern_certificate.html", {
#             "recipient_name": recipient_name,
#             "internship_field": field,
#             "project_name": project,
#             "start_date": start_date,
#             "end_date": end_date,
#             "issued_at": make_aware(datetime.now()),
#             "certificate_code": certificate_code,
#         })

#         # Save the PDF file
#         pdf_file_name = f"{certificate_code}.pdf"
#         pdf_file_path = os.path.join(settings.MEDIA_ROOT, pdf_file_name)
#         with open(pdf_file_path, "wb") as pdf_file:
#             pisa_status = pisa.CreatePDF(html_content, dest=pdf_file)

#         if pisa_status.err:
#             error_message = "Failed to generate PDF."
#             return render(request, 'issue_certificate.html', {'error': error_message})

#         # Email body with verification link
#         email_body = f"""
#         Dear {recipient_name},

#         Congratulations on successfully completing your {certificate_type}!

#         You can verify and download your certificate using the following link:
#         http://127.0.0.1:8000/media/{pdf_file_name}

#         Best regards,
#         CodMinds Team
#         """

#         # Prepare and send the email
#         email_message = EmailMessage(
#             subject=f"Your {certificate_type.capitalize()} Certificate",
#             body=email_body,
#             from_email="codmindsofficial@gmail.com",
#             to=[email],
#         )
#         email_message.attach_file(pdf_file_path)  # Attach the PDF file
#         email_message.send()

#         # Success message for the user
#         success = "Certificate issued, emailed, and saved as PDF successfully!"
#         return render(request, 'issue_certificate.html', {'success': success})

#     return render(request, "issue_certificate.html")
