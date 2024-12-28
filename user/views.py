from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse
from django.contrib import messages
from .models import *
from certificate.models import *
from authority.models import *
from django.db import IntegrityError
import hashlib
import re
from django.core.exceptions import ValidationError
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

# Razorpay Client Setup
razorpay_client = razorpay.Client(
    auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

logger = logging.getLogger(__name__)

def user_signup(request):
    if request.method == 'POST':
        # Get the data from the form
        name = request.POST.get('name')
        email = request.POST.get('email')
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
            messages.error(request, "Phone number must be a 10-digit number.")
            return render(request, 'signup.html')

        try:
            # Check if the email or phone number is already taken
            if User.objects.filter(email=email).exists():
                messages.error(request, "Email already taken.")
                return render(request, 'signup.html')
            if User.objects.filter(phone=phone).exists():
                messages.error(request, "phone number already taken.")
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
    else:
        return render(request, 'signup.html')


def user_login(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        # Hash the entered password to compare it with the stored one
        hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()

        try:
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

    else:
        # GET request, just render the login page
        return render(request, 'login.html')

def user_logout(request):
    request.session.flush()
    return redirect('user_login')

# Forgot Password View


def forgot_password(request):
    if request.method == "POST":
        email = request.POST.get('email')

        # Check if email exists in the database
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            messages.error(request, "Email not found.")
            return redirect('forgot_password')

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

        return redirect('verify_otp')  # Redirect to OTP verification page

    return render(request, 'forgot_password.html')
    
# OTP Verification View


def verify_otp(request):
    if request.method == "POST":
        otp_entered = request.POST.get('otp')

        if str(request.session.get('otp')) == otp_entered:
            # Redirect to password reset page
            return redirect('reset_password')
        else:
            messages.error(request, "Invalid OTP. Please try again.")
            # Stay on OTP verification page
            return render(request, 'verify_otp.html')

    return render(request, 'verify_otp.html')

# Password Reset View


def reset_password(request):
    if request.method == "POST":
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        if password == confirm_password:
            email = request.session.get('email')  # Get email from session
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                messages.error(request, "User not found.")
                return redirect('forgot_password')

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

    return render(request, 'reset_password.html')

def user_dashboard(request):
    user = User.objects.get(email=request.session.get('email'))
    name = user.name
    try:
        internApplication = InternshipApplication.objects.get(email = request.session.get('email'))
        return render(request, 'user_dashboard.html', {'name': name, 'internApplication': internApplication})
    except:
        return render(request, 'user_dashboard.html', {'name': name})


def user_profile(request):
    # Fetch the currently logged-in user
    user = User.objects.get(email=request.session.get('email'))

    if request.method == 'POST':
        email_original = request.session.get('email')
        # Get the data from the form
        name = request.POST.get('name')
        email = request.POST.get('email')
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
            messages.error(request, "Phone number must be a 10-digit number.")
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
                InternshipAppl = InternshipApplication.objects.get(email = email_original)
                InternshipAppl.email = email
                InternshipAppl.save()

            if InternshipCertificate.objects.filter(email = email_original).exists():
                InternshipCert = InternshipCertificate.objects.get(email = email_original)
                InternshipCert.email = email
                InternshipCert.save()
            
            if Payment.objects.filter(email = email_original).exists():
                pay = Payment.objects.get(email = email_original)
                pay.email = email 
                pay.save()

            if email_original != request.session.get('email_change'):
                request.session['email'] = request.session.get('email_change')

            messages.success(request, "Profile updated successfully.")
            return render(request, 'edit_profile.html', {'user': user})

        except IntegrityError:
            messages.error(
                request, "An error occurred while updating your profile. Please try again.")
            return render(request, 'edit_profile.html', {'user': user})

    # GET request: Render the profile editing page
    return render(request, 'edit_profile.html', {'user': user})

def user_certificates(request):
    try:
        certificates = InternshipCertificate.objects.filter(email=request.session.get('email'))
        return render(request, 'user_certificates.html', {'certificates' : certificates})
    except:
        return render(request, 'user_certificates.html')


def apply_for_internship(request):
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
                errors.append("Resume must be a .pdf, .doc, or .docx file.")
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
            project_name = '', 
            project_description = ''
        )
        application.save()

        messages.success(
            request, "Your application has been submitted successfully!")
        # Redirect back to the form or another page
        return redirect('apply_for_internship')

    return render(request, 'apply_for_internship.html', {'user': user})

def view_internship_application_status(request):
    application = InternshipApplication.objects.get(email=request.session.get('email'))
    return render(request, 'view_internship_application_status.html', {'application': application})


def project_selection(request):
    RAZORPAY_KEY_ID = settings.RAZORPAY_KEY_ID
    internApplication = ''
    user = ''
    projects
    try:
        internApplication = InternshipApplication.objects.get(email = request.session.get('email'))
        user = User.objects.get(email = request.session.get('email'))
        # Fetch all available projects
        projects = InternshipProjects.objects.filter(field = internApplication.department)
    except:
        return redirect('user_login')
        
    for i in projects:
        if internApplication.project_name != '':
            return render(request, 'view_internship_application_status.html', {'err': f'you already selected Project : {i.title}', 'application': internApplication})
    return render(request, 'project_selection.html', {
        'projects': projects,
        'user': user,
        'RAZORPAY_KEY_ID': RAZORPAY_KEY_ID,
    })


def create_order(request):
    if request.method == "POST":
        data = json.loads(request.body)
        project_id = data.get("project_id")
        amount = 9900  # Amount in paise (9900 paise = 99 INR)
        currency = "INR"
        email = str(request.session.get('email'))  # Get email from session

        if not email:
            logger.error("User email not found in session")
            return JsonResponse({'error': 'User email not found in session'}, status=400)

        try:
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
                order_id=order_id, amount=amount / 100, email=email, status='Pending', project_id = project_id
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

            #update internshipapplication data in database
                proj = InternshipProjects.objects.get(id = request.session.get('project_id'))
                duration = proj.duration
                InternProjSelected = InternshipApplication.objects.get(email = request.session.get('email'))
                request.session['name'] = InternProjSelected.name
                request.session['department'] = InternProjSelected.department
                InternProjSelected.project_name = proj.title
                request.session['project_name'] = InternProjSelected.project_name
                InternProjSelected.project_description = proj.description
                InternProjSelected.save()

            # allocate project and do entry in AllottedProject
                start_date = (datetime.now() + timedelta(days=5)).date()
                end_date = start_date + relativedelta(months=duration)
                project_allocated = AllottedProject.objects.create(
                    project_id=request.session.get('project_id'), email=request.session.get('email'), start_date=start_date, end_date=end_date)
                print(start_date, end_date)
                # project_allocated.save()

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

            return JsonResponse({'status': 'success', 'message': 'Payment Verified'}, status=200)
        except json.JSONDecodeError:
            return JsonResponse({'status': 'Failed', 'message': 'Invalid JSON payload'}, status=400)
        except Exception as e:
            return JsonResponse({'status': 'Failed', 'message': f'Error: {str(e)}'}, status=500)

    return JsonResponse({'status': 'Failed', 'message': 'Invalid request method'}, status=400)

def select_project(request, project_id):
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