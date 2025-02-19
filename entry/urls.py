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

    path('page-not-found/', error_404_view, name='error_404_view'),
]
