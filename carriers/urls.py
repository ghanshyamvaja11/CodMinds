from django.urls import path
from . import views

urlpatterns = [
    path('post_vacancy/', views.post_vacancy, name='post_vacancy'),
    path('job_applications/', views.job_applications, name='job_applications'),
    path('update_application_status/<int:application_id>/',
         views.update_application_status, name='update_application_status'),
]
