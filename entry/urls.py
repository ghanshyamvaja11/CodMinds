from django.urls import path
from .views import *

urlpatterns = [
    path('', home, name='home'),
    path('about/', about,
         name='about'),  # Redirect after login
    path('servicies/', services, name='servicies'),
    path('contact/', contact, name='contact'),
    path('terms-and-conditions/', T_and_C, name='T&C'),
    path('privacy-policy/', Privacy_policy, name="privacy-policy"),
    path('cancellation-refund_policies/', cancellation_refund_policies,
         name='cancellation_refund_policies'),
]
