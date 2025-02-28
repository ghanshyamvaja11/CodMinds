from django.urls import path
from .views import *

urlpatterns = [
    path('', home, name='home'),
    path('about', about,
         name='about'),  # Redirect after login
    path('servicies', services, name='servicies'),
    path('contact', contact, name='contact'),
    path('terms-and-conditions', T_and_C, name='T&C'),
    path('privacy-policy', privacy_policy, name="privacy_policy"),
    path('cancellation-refund-policies', cancellation_refund_policies,
         name='cancellation_refund_policies'),
    path('servicies/internship-program',
         internship_program, name='internship_program'),
    path('servicies/web-development', web_development, name='web_development'),
    path('servicies/software-development', software_development,
         name='software_development'),
    path('servicies/data-analytics', data_analytics, name='data_analytics'),
    path('page-not-found/', error_404_view, name='error_404_view'),
    path('hire_us', hire_us, name='hire_us'),
]
