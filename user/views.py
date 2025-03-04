from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse, HttpResponse
from django.contrib import messages
from .models import *
from certificate.models import *
from authority.models import *
from django.db import IntegrityError
import hashlib
import re
from django.core.exceptions import ValidationError, ObjectDoesNotExist
from django.core.validators import validate_email
from django.core.mail import send_mail
import random
import hashlib
import json
from django.views.decorators.csrf import csrf_exempt
import razorpay
from django.conf import settings
import logging
from dateutil.relativedelta import relativedelta
from datetime import datetime, timedelta
import os
from django.contrib.messages import get_messages
from carriers.models import Vacancy, JobApplication

# Razorpay Client Setup
razorpay_client = razorpay.Client(
    auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

logger = logging.getLogger(__name__)


def clear_messages(request):
    storage = get_messages(request)
    for _ in storage:
        pass


def user_signup(request):
    clear_messages(request)
    if request.method == 'POST':
        try:
            # Get the data from the form
            name = request.POST.get('name')
            # Convert email to lowercase
            email = request.POST.get('email').lower()
            phone = request.POST.get('phone')
            password = request.POST.get('password')
            confirm_password = request.POST.get('confirm_password')

            # Check if passwords match
            if password != confirm_password:
                messages.error(request, "Passwords do not match.")
                return render(request, 'signup.html')

            # Email validation
            try:
                validate_email(email)
            except ValidationError:
                messages.error("Enter a valid email address.")
                return render(request, 'signup.html')

            # Phone validation
            if not phone or not re.match(r'^\d{10}$', phone):
                messages.error(
                    request, "Phone number must be a 10-digit number.")
                return render(request, 'signup.html')

            # Check if the email or phone number is already taken
            if User.objects.filter(email=email).exists():
                messages.error(request, "Email already taken.")
                return render(request, 'signup.html')
            if User.objects.filter(phone=phone).exists():
                messages.error(request, "Phone number already taken.")
                return render(request, 'signup.html')

            # Hash the password
            hashed_password = hashlib.sha256(
                password.encode('utf-8')).hexdigest()

            # Create a new user instance
            new_user = User(name=name, email=email,
                            phone=phone, password=hashed_password)
            new_user.save()

            # Optionally, you can add the user to the session and redirect to the login page
            messages.success(
                request, "Account created successfully! Please login.")
            return redirect('user_login')

        except IntegrityError:
            # Handle cases where there's a database integrity error
            messages.error(
                request, "Error creating account. Please try again.")
            return render(request, 'signup.html')
        except Exception as e:
            logger.error(f"Unexpected error during signup: {str(e)}")
            messages.error(
                request, "An unexpected error occurred. Please try again.")
            return render(request, 'signup.html')
    else:
        return render(request, 'signup.html')


def user_login(request):
    clear_messages(request)
    if request.method == 'POST':
        try:
            # Convert email to lowercase
            email = request.POST.get('email').lower()
            password = request.POST.get('password')
            # Hash the entered password to compare it with the stored one
            hashed_password = hashlib.sha256(
                password.encode('utf-8')).hexdigest()

            # Try to find the user by email and password
            user = User.objects.get(email=email, password=hashed_password)
            # Set session variables on successful login
            request.session['email'] = user.email
            # Redirect to dashboard after successful login
            return redirect('user_dashboard')
        except User.DoesNotExist:
            # If user not found, show an error message
            messages.error(request, "Invalid email or password.")
            return render(request, 'login.html')
        except Exception as e:
            logger.error(f"Unexpected error during login: {str(e)}")
            messages.error(
                request, "An unexpected error occurred. Please try again.")
            return render(request, 'login.html')
    else:
        # GET request, just render the login page
        return render(request, 'login.html')


def user_logout(request):
    clear_messages(request)
    try:
        request.session.flush()
    except Exception as e:
        logger.error(f"Unexpected error during logout: {str(e)}")
    return redirect('user_login')

# Forgot Password View


def forgot_password(request):
    clear_messages(request)
    if request.method == "POST":
        try:
            # Convert email to lowercase
            email = request.POST.get('email').lower()

            # Check if email exists in the database
            user = User.objects.get(email=email)

            # Store email in session for later use
            request.session['email'] = email

            # Generate OTP and send it via email
            otp = random.randint(100000, 999999)
            # Store OTP in session for verification
            request.session['otp'] = otp
            send_mail(
                'Your OTP for Password Reset',
                f'Your OTP code is: {otp}',
                'codmindsofficial@gmail.com',
                [email],
                fail_silently=False,
            )

            return redirect('verify_otp')  # Redirect to OTP verification page
        except User.DoesNotExist:
            messages.error(request, "Email not found.")
            return redirect('forgot_password')
        except Exception as e:
            logger.error(f"Unexpected error during forgot password: {str(e)}")
            messages.error(
                request, "An unexpected error occurred. Please try again.")
            return redirect('forgot_password')

    return render(request, 'forgot_password.html')

# OTP Verification View


def verify_otp(request):
    clear_messages(request)
    if request.method == "POST":
        try:
            otp_entered = request.POST.get('otp')

            if str(request.session.get('otp')) == otp_entered:
                # Redirect to password reset page
                return redirect('reset_password')
            else:
                messages.error(request, "Invalid OTP. Please try again.")
                # Stay on OTP verification page
                return render(request, 'verify_otp.html')
        except Exception as e:
            logger.error(f"Unexpected error during OTP verification: {str(e)}")
            messages.error(
                request, "An unexpected error occurred. Please try again.")
            return render(request, 'verify_otp.html')

    return render(request, 'verify_otp.html')

# Password Reset View


def reset_password(request):
    clear_messages(request)
    if request.method == "POST":
        try:
            password = request.POST.get('password')
            confirm_password = request.POST.get('confirm_password')

            if password == confirm_password:
                email = request.session.get('email')  # Get email from session
                user = User.objects.get(email=email)

                # Hash the password
                hashed_password = hashlib.sha256(
                    password.encode('utf-8')).hexdigest()
                user.password = hashed_password
                user.save()
                messages.success(request, "Password successfully reset!")
                # Redirect to login after resetting password
                return redirect('user_login')
            else:
                messages.error(request, "Passwords do not match.")
                # Stay on reset password page
                return render(request, 'reset_password.html')
        except User.DoesNotExist:
            messages.error(request, "User not found.")
            return redirect('forgot_password')
        except Exception as e:
            logger.error(f"Unexpected error during password reset: {str(e)}")
            messages.error(
                request, "An unexpected error occurred. Please try again.")
            return render(request, 'reset_password.html')

    return render(request, 'reset_password.html')


def user_dashboard(request):
    clear_messages(request)
    try:
        user = User.objects.get(email=request.session.get('email'))
        name = user.name
        try:
            internApplication = InternshipApplication.objects.get(
                email=request.session.get('email'))
            return render(request, 'user_dashboard.html', {'name': name, 'internApplication': internApplication})
        except InternshipApplication.DoesNotExist:
            return render(request, 'user_dashboard.html', {'name': name})
    except User.DoesNotExist:
        messages.error(request, "User not found.")
        return redirect('user_login')
    except Exception as e:
        logger.error(f"Unexpected error during dashboard access: {str(e)}")
        messages.error(
            request, "An unexpected error occurred. Please try again.")
        return redirect('user_login')

def internship_dashboard(request):
    return render(request, 'user_intern_dashboard.html')

def job_dashboard(request):
    return render(request, 'user_job_dashboard.html')

def user_profile(request):
    clear_messages(request)
    try:
        # Fetch the currently logged-in user
        user = User.objects.get(email=request.session.get('email'))

        if request.method == 'POST':
            email_original = request.session.get('email')
            # Get the data from the form
            name = request.POST.get('name')
            # Convert email to lowercase
            email = request.POST.get('email').lower()
            phone = str(request.POST.get('phone'))
            password = request.POST.get('password')

            request.session['email_change'] = email

            # Validate email
            try:
                validate_email(email)
            except ValidationError:
                messages.error(request, "Enter a valid email address.")
                return render(request, 'edit_profile.html', {'user': user})

            # Validate phone number (10 digits only)
            if not re.match(r'^\d{10}$', phone):
                messages.error(
                    request, "Phone number must be a 10-digit number.")
                return render(request, 'edit_profile.html', {'user': user})

            try:
                # Hash the password if provided
                if password:
                    hashed_password = hashlib.sha256(
                        password.encode('utf-8')).hexdigest()
                    user.password = hashed_password

                # Update user details
                user.name = name
                user.email = email
                user.phone = phone
                user.save()

                if InternshipApplication.objects.filter(email=email_original).exists():
                    InternshipAppl = InternshipApplication.objects.get(
                        email=email_original)
                    InternshipAppl.email = email
                    InternshipAppl.save()

                if InternshipCertificate.objects.filter(email=email_original).exists():
                    InternshipCert = InternshipCertificate.objects.get(
                        email=email_original)
                    InternshipCert.email = email
                    InternshipCert.save()

                if Payment.objects.filter(email=email_original).exists():
                    pay = Payment.objects.get(email=email_original)
                    pay.email = email
                    pay.save()

                if email_original != request.session.get('email_change'):
                    request.session['email'] = request.session.get(
                        'email_change')

                messages.success(request, "Profile updated successfully.")
                return render(request, 'edit_profile.html', {'user': user})

            except IntegrityError:
                messages.error(
                    request, "An error occurred while updating your profile. Please try again.")
                return render(request, 'edit_profile.html', {'user': user})
            except Exception as e:
                logger.error(
                    f"Unexpected error during profile update: {str(e)}")
                messages.error(
                    request, "An unexpected error occurred. Please try again.")
                return render(request, 'edit_profile.html', {'user': user})

        # GET request: Render the profile editing page
        return render(request, 'edit_profile.html', {'user': user})
    except User.DoesNotExist:
        messages.error(request, "User not found.")
        return redirect('user_login')
    except Exception as e:
        logger.error(f"Unexpected error during profile access: {str(e)}")
        messages.error(
            request, "An unexpected error occurred. Please try again.")
        return redirect('user_login')


def user_certificates(request):
    clear_messages(request)
    try:
        certificates = InternshipCertificate.objects.filter(
            email=request.session.get('email'))
        return render(request, 'user_certificates.html', {'certificates': certificates})
    except Exception as e:
        logger.error(f"Unexpected error during certificate access: {str(e)}")
        messages.error(
            request, "An unexpected error occurred. Please try again.")
        return render(request, 'user_certificates.html')


def apply_for_internship(request):
    clear_messages(request)
    try:
        user = User.objects.get(email=request.session.get('email'))
        if request.method == 'POST':
            name = user.name
            email = user.email
            phone = user.phone
            department = request.POST.get('department')
            cover_letter = request.POST.get('cover_letter')
            resume = request.FILES.get('resume')

            # Validation flags
            errors = []

            # Check if the user already applied for this internship
            try:
                existing_application = InternshipApplication.objects.get(
                    email=email)
                errors.append(
                    f"You have already applied for the {existing_application.department} internship.")
            except InternshipApplication.DoesNotExist:
                pass  # No previous application, so continue

            # Name validation
            if not name or len(name) < 3:
                errors.append("Name must be at least 3 characters long.")

            # Email validation
            try:
                validate_email(email)
            except ValidationError:
                errors.append("Enter a valid email address.")

            # Phone validation
            if not phone or not re.match(r'^\d{10}$', phone):
                errors.append("Phone number must be a 10-digit number.")

            # Department validation
            if not department or department not in ['web-development', 'data-science', 'cyber-security', 'ai-ml']:
                errors.append("Please select a valid department.")

            # Resume validation
            if resume:
                if not resume.name.endswith(('.pdf', '.doc', '.docx')):
                    errors.append(
                        "Resume must be a .pdf, .doc, or .docx file.")
                if resume.size > 2 * 1024 * 1024:  # 2 MB limit
                    errors.append("Resume file size must not exceed 2 MB.")
            else:
                errors.append("Please upload your resume.")

            # If there are errors, show messages and return the form
            if errors:
                for error in errors:
                    messages.error(request, error)
                return render(request, 'apply_for_internship.html', {'user': user})

            # Save the application if no errors
            application = InternshipApplication(
                name=name,
                email=email,
                phone=phone,
                department=department,
                cover_letter=cover_letter,
                resume=resume,
                project_name='',
                project_description=''
            )
            application.save()

            messages.success(
                request, "Your application has been submitted successfully!")
            # Redirect back to the form or another page
            return redirect('apply_for_internship')

        return render(request, 'apply_for_internship.html', {'user': user})
    except User.DoesNotExist:
        messages.error(request, "User not found.")
        return redirect('user_login')
    except Exception as e:
        logger.error(
            f"Unexpected error during internship application: {str(e)}")
        messages.error(
            request, "An unexpected error occurred. Please try again.")
        return redirect('apply_for_internship')


def view_internship_application_status(request):
    clear_messages(request)
    try:
        application = InternshipApplication.objects.get(
            email=request.session.get('email'))
        return render(request, 'view_internship_application_status.html', {'application': application})
    except InternshipApplication.DoesNotExist:
        messages.error(request, "Application not found.")
        return redirect('apply_for_internship')
    except Exception as e:
        logger.error(
            f"Unexpected error during application status view: {str(e)}")
        messages.error(
            request, "An unexpected error occurred. Please try again.")
        return redirect('apply_for_internship')


def project_selection(request):
    clear_messages(request)
    try:
        RAZORPAY_KEY_ID = settings.RAZORPAY_KEY_ID
        internApplication = InternshipApplication.objects.get(
            email=request.session.get('email'))
        user = User.objects.get(email=request.session.get('email'))
        # Fetch all available projects
        projects = InternshipProjects.objects.filter(
            field=internApplication.department)

        for i in projects:
            if internApplication.project_name != '':
                return render(request, 'view_internship_application_status.html', {'err': f'you already selected Project : {i.title}', 'application': internApplication})
        return render(request, 'project_selection.html', {
            'projects': projects,
            'user': user,
            'RAZORPAY_KEY_ID': RAZORPAY_KEY_ID,
        })
    except InternshipApplication.DoesNotExist:
        messages.error(request, "Internship application not found.")
        return redirect('apply_for_internship')
    except User.DoesNotExist:
        messages.error(request, "User not found.")
        return redirect('user_login')
    except Exception as e:
        logger.error(f"Unexpected error during project selection: {str(e)}")
        messages.error(
            request, "An unexpected error occurred. Please try again.")
        return redirect('user_dashboard')


def create_order(request):
    clear_messages(request)
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            project_id = data.get("project_id")
            amount = 9900  # Amount in paise (9900 paise = 99 INR)
            currency = "INR"
            email = str(request.session.get('email'))  # Get email from session

            if not email:
                logger.error("User email not found in session")
                return JsonResponse({'error': 'User email not found in session'}, status=400)

            order_info = {
                "amount": amount,
                "currency": currency,
                "payment_capture": 1  # Automatically capture payment
            }
            # Create the Razorpay order
            order = razorpay_client.order.create(order_info)
            order_id = order.get('id')
            if not order_id:
                logger.error(
                    "Failed to retrieve order_id from Razorpay response")
                return JsonResponse({'error': 'Failed to create Razorpay order try again'}, status=500)

            # Save payment details to the database
            payment = Payment.objects.create(
                order_id=order_id, amount=amount / 100, email=email, status='Pending', project_id=project_id
            )

            request.session['project_id'] = project_id

            logger.info(f"Payment created successfully: {payment}")

            return JsonResponse({'order_id': order_id, 'amount': amount, 'email': email})
        except Exception as e:
            logger.error(f"Error creating Razorpay order: {str(e)}")
            return JsonResponse({'error': f'Error creating Razorpay order: {str(e)}'}, status=500)

    logger.error("Invalid request method for create_order")
    return JsonResponse({'error': 'Invalid request method'}, status=400)


def verify_payment(request):
    clear_messages(request)
    if request.method == "POST":
        try:
            # Parse JSON payload
            data = json.loads(request.body)
            razorpay_order_id = data.get('razorpay_order_id')
            razorpay_payment_id = data.get('razorpay_payment_id')
            razorpay_signature = data.get('razorpay_signature')

            if not all([razorpay_order_id, razorpay_payment_id, razorpay_signature]):
                return JsonResponse({'status': 'Failed', 'message': 'Invalid payment data'}, status=400)

            # Verify the payment signature
            params_dict = {
                'razorpay_order_id': razorpay_order_id,
                'razorpay_payment_id': razorpay_payment_id,
                'razorpay_signature': razorpay_signature
            }

            try:
                # Signature verification
                razorpay_client.utility.verify_payment_signature(params_dict)
            except razorpay.errors.SignatureVerificationError:
                return JsonResponse({'status': 'Failed', 'message': 'Payment verification failed. Invalid signature.'}, status=400)

            # Update payment status in the database
            try:
                payment = Payment.objects.get(order_id=razorpay_order_id)
                payment.payment_id = razorpay_payment_id
                payment.signature = razorpay_signature
                payment.status = 'Completed'
                payment.refund_amount = 0
                payment.save()

            # update internshipapplication data in database
                proj = InternshipProjects.objects.get(
                    id=request.session.get('project_id'))
                duration = proj.duration
                InternProjSelected = InternshipApplication.objects.get(
                    email=request.session.get('email'))
                request.session['name'] = InternProjSelected.name
                request.session['department'] = InternProjSelected.department
                InternProjSelected.project_name = proj.title
                request.session['project_name'] = InternProjSelected.project_name
                InternProjSelected.project_description = proj.description
                InternProjSelected.save()

            # allocate project and do entry in AllottedProject
                current_date = datetime.now().date()

                # Add 5 days to the current date
                start_date = current_date + timedelta(days=5)

                end_date = start_date + relativedelta(months=duration)
                project_allocated = AllottedProject.objects.create(
                    project_id=request.session.get('project_id'), email=request.session.get('email'), start_date=start_date, end_date=end_date)
                project_allocated.save()

                name = request.session.get('name')
                department = request.session.get('department')
                project_name = request.session.get('project_name')

                subject = "Payment Confirmation for Internship Project Selection"
                message = (
                    f"Hello {name},\n\n"
                    f"Thank you for completing the payment of Rs. 99 for selecting your internship project in the {department} department.\n\n"
                    f"Project Name: {project_name}\n"
                    f"Project Duration: {duration}\n"
                    f"Internship Start Date: {start_date}\n"
                    f"internship End Date: {end_date}\n\n"
                    f"Payment Details:\n"
                    f"Order ID: {payment.order_id}\n"
                    f"Payment ID: {payment.payment_id}\n\n"
                    f"Your payment has been successfully verified. We appreciate your interest and wish you the best for your internship!\n\n"
                    f"You will get your offer letter shortly."
                    f"Regards,\nCodMinds Team"
                )

                send_mail(
                    subject,
                    message,
                    'noreply@codminds.com',  # Replace with your sender email
                    [payment.email],
                    fail_silently=False
                )

            except Payment.DoesNotExist:
                return JsonResponse({'status': 'Failed', 'message': 'Payment record not found'}, status=404)
            try:
                payment = Payment.objects.get(order_id=razorpay_order_id)

                # Check if the status is 'Completed'
                if (payment.status != 'Completed'):
                    payment.delete()  # Delete the payment if the status is not 'Completed'

            except ObjectDoesNotExist:
                # Handle the case where no matching Payment record is found
                pass

            return JsonResponse({'status': 'success', 'message': 'Payment Verified'}, status=200)
        except json.JSONDecodeError:
            return JsonResponse({'status': 'Failed', 'message': 'Invalid JSON payload'}, status=400)
        except Exception as e:
            return JsonResponse({'status': 'Failed', 'message': f'Error: {str(e)}'}, status=500)

    return JsonResponse({'status': 'Failed', 'message': 'Invalid request method'}, status=400)


def select_project(request, project_id):
    clear_messages(request)
    try:
        # Fetch the project by ID
        project = get_object_or_404(InternshipProjects, id=project_id)

        # Fetch the logged-in user's application
        application = InternshipApplication.objects.filter(
            email=request.session.get('email'), status=1).first()

        if application:
            # Assign the selected project to the application
            application.project_name = project.title
            application.project_description = project.description
            application.save()

            # Redirect to the application view after project selection
            # Adjust the name of the view
            return redirect('view_internship_application_status')

        return redirect('project_selection')
    except Exception as e:
        logger.error(f"Unexpected error during project selection: {str(e)}")
        messages.error(
            request, "An unexpected error occurred. Please try again.")
        return redirect('project_selection')


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


def login_with_otp(request):
    clear_messages(request)
    if request.method == 'POST':
        email = request.POST.get('email').lower()
        try:
            user = User.objects.get(email=email)
            otp = random.randint(100000, 999999)
            request.session['otp'] = otp
            request.session['email'] = email
            send_mail(
                'Your OTP for Login',
                f'Your OTP code is: {otp}',
                'codmindsofficial@gmail.com',
                [email],
                fail_silently=False,
            )
            return redirect('verify_login_otp')
        except User.DoesNotExist:
            messages.error(request, "Email not found.")
            return redirect('login_with_otp')
    return render(request, 'login_with_otp.html')


def verify_login_otp(request):
    clear_messages(request)
    if request.method == 'POST':
        otp_entered = request.POST.get('otp')
        if str(request.session.get('otp')) == otp_entered:
            email = request.session.get('email')
            user = User.objects.get(email=email)
            request.session['email'] = user.email
            return redirect('user_dashboard')
        else:
            messages.error(request, "Invalid OTP. Please try again.")
            return render(request, 'verify_login_otp.html')
    return render(request, 'verify_login_otp.html')


def jobs(request):
    clear_messages(request)
    try:
        user_email = request.session.get('email')
        vacancies = Vacancy.objects.filter(
            is_active=True, last_date_of_application__gte=timezone.now().date()
        ).order_by('-posted_date')

        applied_jobs = JobApplication.objects.filter(
            applicant_email=user_email).values_list('vacancy_id', flat=True)

        return render(request, 'jobs.html', {'vacancies': vacancies, 'applied_jobs': applied_jobs})
    except Exception as e:
        logger.error(f"Unexpected error during fetching jobs: {str(e)}")
        messages.error(
            request, "An unexpected error occurred. Please try again.")
        return render(request, 'jobs.html', {'vacancies': [], 'applied_jobs': []})


def apply_for_job(request, vacancy_id):
    clear_messages(request)
    try:
        vacancy = get_object_or_404(Vacancy, id=vacancy_id)
        if request.method == 'POST':
            applicant_name = request.POST.get('applicant_name')
            applicant_email = request.POST.get('applicant_email')
            resume = request.FILES.get('resume')
            cover_letter = request.POST.get('cover_letter')

            # Validate form data
            if not applicant_name or not applicant_email or not resume or not cover_letter:
                messages.error(request, "All fields are required.")
                return render(request, 'apply_for_job.html', {'vacancy': vacancy})

            # Save the job application
            job_application = JobApplication(
                vacancy=vacancy,
                applicant_name=applicant_name,
                applicant_email=applicant_email,
                resume=resume,
                cover_letter=cover_letter
            )
            job_application.save()

            messages.success(
                request, "Your application has been submitted successfully!")
            return redirect('jobs')

        return render(request, 'apply_for_job.html', {'vacancy': vacancy})
    except Exception as e:
        logger.error(f"Unexpected error during job application: {str(e)}")
        messages.error(
            request, "An unexpected error occurred. Please try again.")
        return redirect('jobs')


def user_job_applications(request):
    clear_messages(request)
    try:
        user_email = request.session.get('email')
        job_applications = JobApplication.objects.filter(
            applicant_email=user_email)
        return render(request, 'user_job_applications.html', {'job_applications': job_applications})
    except Exception as e:
        logger.error(
            f"Unexpected error during fetching job applications: {str(e)}")
        messages.error(
            request, "An unexpected error occurred. Please try again.")
        return render(request, 'user_job_applications.html', {'job_applications': []})
