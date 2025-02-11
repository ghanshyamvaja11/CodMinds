from datetime import timedelta
from user.models import *
from django.shortcuts import render
from user.models import *
from django.http import JsonResponse, HttpResponseRedirect
from django.shortcuts import redirect, reverse
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
from datetime import datetime, timedelta
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
from django.urls import reverse
from django.conf import settings
import razorpay
from django.contrib.messages import get_messages

# Razorpay Client Setup
razorpay_client = razorpay.Client(
    auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

def clear_messages(request):
    storage = get_messages(request)
    for _ in storage:
        pass

def admin_login(request):
    clear_messages(request)
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
    clear_messages(request)
    return render(request, 'admin_dashboard.html')


def admin_logout(request):
    clear_messages(request)
    # Handle both GET and POST methods
    if request.method in ['POST', 'GET']:
        logout(request)  # Log out the user
        # Ensure 'admin_login' is a valid URL name
        request.session.flush()
        return redirect('admin_login')
    else:
        # If the method is neither GET nor POST, fallback to the login page
        return redirect('admin_login')

# Forgot Password View


def forgot_password(request):
    clear_messages(request)
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
    clear_messages(request)
    if request.method == "POST":
        otp_entered = request.POST.get('otp')

        if str(request.session.get('otp')) == otp_entered:
            return redirect('admin_reset_password')
        else:
            messages.error(request, "Invalid OTP. Please try again.")
            return render(request, 'admin_verify_otp.html')

    return render(request, 'admin_verify_otp.html')

# Password Reset View
def reset_password(request):
    clear_messages(request)
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

#Add Internship Projects
def add_internship_project(request):
    clear_messages(request)
    if request.method == 'POST':
        # Extract form data from POST request
        field = request.POST.get('field')
        title = request.POST.get('title')
        description = request.POST.get('description')
        duration = request.POST.get('duration')

        # Create and save new internship project
        project = InternshipProjects(
            field=field,
            title=title,
            description=description,
            duration=duration
        )
        project.save()

        # Optionally display a success message
        success_message = "Internship project added successfully!"

        return render(request, 'add_internship_project.html', {'success': success_message})

    return render(request, 'add_internship_project.html')


def view_internship_applications(request):
    clear_messages(request)
    applications = InternshipApplication.objects.all()
    return render(request, 'view_internship_applications.html', {'applications': applications})

# Approve or Reject Internship Application
def approve_or_reject_application(request, app_id):
    clear_messages(request)
    # Fetch the internship application by ID
    application = get_object_or_404(InternshipApplication, id=app_id)

    if request.method == 'POST':
        status = request.POST.get('status')

        if status == 'approved':
            application.status = 1  # Mark the status as approved
            # Send email to the user if selected
            send_mail(
                'Internship Application Status: Approved',
                f'Congratulations {application.name}! Your application for the internship has been approved. Please log in to your dashboard and select a project of your choice.',
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
    clear_messages(request)
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

#Provide Offer letter
def eligible_for_internship_offer_letter(request):
    clear_messages(request)
    users = None
    try:
        # Assuming you want to fetch all applications where project_name is not empty
        users = InternshipApplication.objects.filter(
            project_name__isnull=False, offer_letter=False).exclude(project_name='')
    except Exception as e:
        # Handle exceptions if any, or log the error
        pass

    if users:
        # If users exist, pass them to the template
        return render(request, 'eligible_for_offer_letter.html', {'users': users})
    else:
        # If no users are found, render a different template or pass an empty list
        return render(request, 'eligible_for_offer_letter.html', {'users': []})


def download_internship_offer_letter(request):
    clear_messages(request)
    email = ''

    # Check if email is provided in the GET request, else use session
    if request.method == 'GET':
        email = request.GET.get(
            'email', '') or request.session.get('email', '')
        if email:
            request.session['email'] = email  # Store email in session

    # Fetch the internship application based on the email
    try:
        application = InternshipApplication.objects.get(email=email)
    except InternshipApplication.DoesNotExist:
        # Handle case where the email doesn't match an existing application
        return render(request, 'error.html', {'message': 'Internship application not found for this email.'})

    # Fetch the allotted project details using the email
    try:
        allotted_project = AllottedProject.objects.get(email=email)
    except AllottedProject.DoesNotExist:
        # If no project is allotted, you can either handle this scenario or leave the project fields as None
        allotted_project = None

    # Calculate the duration between the start and end date
    if allotted_project:
        duration = (allotted_project.end_date.year - allotted_project.start_date.year) * \
            12 + allotted_project.end_date.month - allotted_project.start_date.month
    else:
        duration = 0  # Default duration in case no project is allotted

    # Fetch the project details
    project_details = None
    if allotted_project:
        try:
            project_details = InternshipProjects.objects.get(
                id=allotted_project.project_id)
        except InternshipProjects.DoesNotExist:
            project_details = None

    # Prepare context data for rendering the offer letter
    context = {
        'name': application.name,
        # Display the department's readable name
        'department': application.department,
        'project_name': application.project_name,
        'duration': duration,
        'start_date': allotted_project.start_date if allotted_project else None,
        'end_date': allotted_project.end_date if allotted_project else None,
        'confirmation_date': allotted_project.start_date + timedelta(days=3) if allotted_project else None,
        # Display project title if available
        'project_title': project_details.title if project_details else 'Not assigned',
        'project_description': project_details.description if project_details else 'No project assigned',
    }

    return render(request, 'issue_internship_offer_letter.html', context)


def issue_internship_offer_letter(request):
    clear_messages(request)
    # Check if POST request and handle file upload
    if request.method == 'POST' and request.FILES['certificate_file']:
        certificate_file = request.FILES['certificate_file']

        # Define where to store the file
        fs = FileSystemStorage()
        filename = fs.save(certificate_file.name, certificate_file)
        uploaded_file_url = fs.url(filename)

        # Get email from session
        email = request.session.get('email')

        if email:
            try:
                # Email content without dates
                subject = "Internship Offer Letter"
                from_email = settings.DEFAULT_FROM_EMAIL
                to_email = email

                message = """
Dear Applicant,

We are pleased to offer you an internship position. Please find the offer letter attached.

Best regards,
CodMinds Team
"""

                # Create the email object and attach the file
                email_message = EmailMessage(
                    subject,
                    message,
                    from_email,
                    [to_email],
                )
                # Attach the uploaded file
                email_message.attach_file(fs.path(filename))

                # Send the email
                email_message.send(fail_silently=False)

                # Success message
                messages.success(request, "Offer letter sent successfully.")
                offer_letter = InternshipApplication.objects.get(email=email)
                offer_letter.offer_letter = True
                offer_letter.save()

                return redirect('issue_internship_offer_letter')

            except Exception as e:
                messages.error(request, f"An error occurred: {str(e)}")
                return HttpResponse(f"Error: {str(e)}")
        else:
            messages.error(request, "Email not found in session.")
            return HttpResponse("Email not found in session.")
    else:
        # GET request or no file uploaded
        return render(request, 'issue_internship_offer_letter.html')
    

#Recieved Payments
def received_internship_payments(request):
    clear_messages(request)
    received_payments_list = Payment.objects.all()

    return render(request, 'recieved_internship_payments.html', {'received_payments_list': received_payments_list})


# Refund
def process_refund(request, payment_id):
    clear_messages(request)
    """
    Processes a refund for the given Razorpay payment ID.
    Updates the database with refund details after successful processing.
    Sends an email notification to the user after the refund.
    """
    if request.method == 'POST':
        try:
            # Get the refund amount from the form and convert to paise (Razorpay works in paise)
            refund_amount = int(request.POST.get('refund_amount')) * 100
            if refund_amount <= 0:
                messages.error(
                    request, "Refund amount must be greater than 0.")
                return redirect(request.META.get('HTTP_REFERER', '/'))

            # Fetch the payment from the database using the payment_id
            payment = Payment.objects.get(payment_id=payment_id)

            # Create refund through Razorpay
            refund_response = razorpay_client.payment.refund(
                payment_id, {"amount": refund_amount})

            if refund_response['status'] == 'processed':
                # Update the payment record with the refund details
                payment.refund_payment_id = refund_response['id']
                payment.refund_amount = refund_amount / 100  # Convert back to rupees
                payment.status = 'Completed'  # Update status to 'Completed' after refund
                payment.save()

                user = User.objects.get(email = payment.email)

                # Send email notification to user
                send_mail(
                    subject="Refund Processed Successfully",
                    message=f"Dear {user.name},\n\nYour refund of Rs. {refund_amount / 100} has been successfully processed for Payment ID {payment_id}.\n\nBest Regards,\nCodMinds",
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[payment.email],
                )

                messages.success(
                    request, f"Refund successful for Payment ID {payment_id}.")
            else:
                messages.info(
                    request, f"Refund initiated for Payment ID {payment_id}. Status: {refund_response['status']}")

        except Payment.DoesNotExist:
            messages.error(request, f"Payment with ID {payment_id} not found.")
        except Exception as e:
            messages.error(request, f"Error processing refund: {str(e)}")

        return HttpResponseRedirect(reverse('received_internship_payments'))

    return JsonResponse({"error": "Invalid request"}, status=400)

# Issue Certificate
def eligible_for_internship_certificate(request):
    clear_messages(request)
    users = InternshipApplication.objects.filter(status=1)
    return render(request, 'eligible_for_certificate.html', {'users': users})

def issue_internship_certificate(request):
    clear_messages(request)
    user = None
    internship = None
    email = request.GET.get('email')

    # Handle GET request
    if request.method == "GET":
        user = User.objects.get(email=email)
        internship = InternshipApplication.objects.get(email=email)
        project_allocated = AllottedProject.objects.get(email=email)

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

    return render(request, "issue_certificate.html", {'user': user, 'internship': internship, 'project_allocated': project_allocated})


# upload Internship certificate
def eligible_interns_for_certificate(request):
    clear_messages(request)
    users = InternshipApplication.objects.filter(status=1)
    return render(request, 'eligible_for_internship_certificate.html', {'users': users})


def upload_internship_certificate(request):
    clear_messages(request)
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
                    email_body = f"Dear {internship_certificate.recipient_name},\n\nPlease find your internship certificate attached.\n\nBest regards,\nCodMinds"
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
    clear_messages(request)
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
    clear_messages(request)
    # Fetch all issued certificates from the database
    issued_certificates = InternshipCertificate.objects.all()

    # Render the template with the context data
    context = {
        'issued_certificates': issued_certificates
    }
    return render(request, 'issued_internship_certificates.html', context)

def contact_us(request):
    clear_messages(request)
    """View to display all contact queries."""
    queries = ContactForm.objects.all()
    return render(request, 'contactus_reply.html', {'queries': queries})


def contact_us_reply(request, query_id):
    clear_messages(request)
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

def added_internship_projects(request):
    clear_messages(request)
    projects = InternshipProjects.objects.all()
    return render(request, 'added_projects.html', {'projects': projects})

def edit_internship_project(request, project_id):
    clear_messages(request)
    project = get_object_or_404(InternshipProjects, id=project_id)

    if request.method == 'POST':
        project.field = request.POST.get('field')
        project.title = request.POST.get('title')
        project.description = request.POST.get('description')
        project.duration = request.POST.get('duration')
        project.save()
        messages.success(request, "Project updated successfully.")
        return redirect('added_internship_projects')

    return render(request, 'edit_project.html', {'project': project})

def delete_internship_project(request, project_id):
    clear_messages(request)
    project = get_object_or_404(InternshipProjects, id=project_id)
    project.delete()
    messages.success(request, "Project deleted successfully.")
    return redirect('added_internship_projects')

def resend_otp(request):
    clear_messages(request)
    if request.method == "POST":
        email = request.session.get('email')
        if email:
            otp = random.randint(100000, 999999)
            request.session['otp'] = otp
            send_mail(
                'Your OTP for Password Reset',
                f'Your OTP code is: {otp}',
                'codmindsofficial@gmail.com',
                [email],
                fail_silently=False,
            )
            return JsonResponse({'success': True})
        return JsonResponse({'success': False, 'message': 'Email not found in session'})
    return JsonResponse({'success': False, 'message': 'Invalid request method'})

def internship_dashboard(request):
    clear_messages(request)
    return render(request, 'internship_dashboard.html')

def admin_login_with_otp(request):
    clear_messages(request)
    if request.method == 'POST':
        email = request.POST.get('email').lower()
        try:
            user = Admin.objects.get(email=email, is_staff=True)
            otp = random.randint(100000, 999999)
            request.session['otp'] = otp
            request.session['email'] = email
            send_mail(
                'Your OTP for Admin Login',
                f'Your OTP code is: {otp}',
                'codmindsofficial@gmail.com',
                [email],
                fail_silently=False,
            )
            return redirect('admin_verify_login_otp')
        except Admin.DoesNotExist:
            messages.error(request, "Email not found or not an admin account.")
            return redirect('admin_login_with_otp')
    return render(request, 'admin_login_with_otp.html')

def admin_verify_login_otp(request):
    clear_messages(request)
    if request.method == 'POST':
        otp_entered = request.POST.get('otp')
        if str(request.session.get('otp')) == otp_entered:
            email = request.session.get('email')
            user = Admin.objects.get(email=email, is_staff=True)
            login(request, user)
            return redirect('admin_dashboard')
        else:
            error_message = "Invalid OTP. Please try again."
            return render(request, 'admin_verify_login_otp.html', {'error_message': error_message})
    return render(request, 'admin_verify_login_otp.html')