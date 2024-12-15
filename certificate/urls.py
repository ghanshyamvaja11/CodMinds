from django.urls import path
from .views import *

urlpatterns = [
    path('intern/verify/',
         verify_certificate, name='verify_certificate'),
    path('intern/verify/<str:certificate_code>/', verify_certificate_by_link, name='verify_certificate_by_link'),
    path("save-certificate/",
         save_certificate, name="save_certificate"),
]