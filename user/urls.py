from django.urls import path
from .views import *
from .views import apply_for_job

# app_name = 'user'

urlpatterns = [
    path('signup', user_signup, name='user_signup'),
    path('login', user_login, name='user_login'),
    path('logout', user_logout, name='user_logout'),
    path('forgot-password', forgot_password, name='forgot_password'),
    path('resend-otp', resend_otp, name='resend_otp'),
    path('verify-otp', verify_otp, name='verify_otp'),
    path('reset-password', reset_password, name='reset_password'),
    path('dashboard', user_dashboard, name='user_dashboard'),
    path('internship-dashboard', internship_dashboard, name='user_intern_dashboard'),
    path('jobs-dashboard', job_dashboard,
         name='job_dashboard'),
    path('dashboard', user_dashboard, name='user_dashboard'),
    path('profile', user_profile, name='user_profile'),
    path('certificates', user_certificates, name='certificates'),
    path('apply-for-internship', apply_for_internship,
         name='apply_for_internship'),
    path('view-internship-application-status', view_internship_application_status,
         name='view_internship_application_status'),
    path('project-selection', project_selection, name='project_selection'),
    #     path('payment', payment_page, name='payment_page'),
    path('create-order', create_order, name='create_order'),
    path('verify-payment', verify_payment, name='verify_payment'),
    path('select-project/<int:project_id>',
         select_project, name='project_select'),
    path('login-with-otp', login_with_otp, name='login_with_otp'),
    path('verify-login-otp', verify_login_otp, name='verify_login_otp'),
    path('carriers/jobs', jobs, name='jobs'),
    path('carriers/apply-for-job/<int:vacancy_id>/',
         apply_for_job, name='apply_for_job'),
    path('carriers/user-job-applications', user_job_applications,
         name='user_job_applications'),
]
