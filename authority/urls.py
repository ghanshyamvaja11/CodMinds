from django.urls import path
from .views import *
from django.contrib.auth.views import LogoutView


urlpatterns = [
    path('', admin_login, name='admin_login'),
    path('logout/', admin_logout, name='admin_logout'),
    path('forgot-password/', forgot_password, name='admin_forgot_password'),
    path('admin_verify-otp/', verify_otp, name='admin_verify_otp'),
    path('resend-otp/', resend_otp, name='admin_resend_otp'),
    path('reset-password/', reset_password, name='admin_reset_password'),
    path('dashboard/', admin_dashboard,
         name='admin_dashboard'),  # Redirect after login
     path('add-internship-project/', add_internship_project, name='add_internship_project'),
    path('view-internship-applications/', view_internship_applications,
         name='view_internship_applications'),
    path('view-internship-applications/<int:app_id>/approve-reject/',
         approve_or_reject_application, name='approve_reject_application'),
    path('project-allocation/<int:app_id>', update_project_allocation, name='update_project_allocation'),
    path('received-payments/', received_payments, name='received_payments'),
    path('process_refund/<str:payment_id>/', process_refund, name='process_refund'),
    path('eligible-for-offer-letter/', eligible_for_offer_letter, name='eligible_for_offer_letter'),
    path('view-offer-letter/', download_offer_letter, name='download_offer_letter'),
    path('send-offer-letter/', send_offer_letter, name='send_offer_letter'),
     path('eligible-for-certificate/', eligible_users, name='eligible_users'),
    path('issue/', issue_certificate, name='issue_certificate'),
    path("certificate/intern/generate/<str:certificate_code>/",
         generate_internship_certificate, name="generate_internship_certificate"),
    path('eligible-for-internship-certificate/', eligible_interns_for_certificate, name='eligible_intern_for_certificate'),
    path('upload_intern_certificate/', upload_internship_certificate,
         name='internship_certificate_upload'),
     path('issued-internship-certificates', issued_internship_certificates, name='issued_internship_certificates'),
    path('contact-us-view/',
         contact_us, name='contact_us_view'),
    path('contact-us-reply/<int:query_id>/',
         contact_us_reply, name='contact_us_reply'),
    path('added-projects/', added_projects, name='added_projects'),
    path('edit-project/<int:project_id>/', edit_project, name='edit_project'),
    path('delete-project/<int:project_id>/', delete_project, name='delete_project'),
]
