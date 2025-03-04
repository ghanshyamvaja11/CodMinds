from django.shortcuts import render, redirect, get_object_or_404
from .models import Vacancy, JobApplication
from django.contrib.auth.decorators import login_required


@login_required
def post_vacancy(request):
    if request.method == 'POST':
        title = request.POST['title']
        description = request.POST['description']
        location = request.POST['location']
        last_date_of_application = request.POST['last_date_of_application']

        Vacancy.objects.create(
            title=title,
            description=description,
            location=location,
            last_date_of_application=last_date_of_application
        )

        return render(request, 'post_vacancy.html', {'success': 'Vacancy posted successfully!'})

    return render(request, 'post_vacancy.html')


@login_required
def job_applications(request):
    applications = JobApplication.objects.all()
    return render(request, 'job_applications.html', {'applications': applications})


@login_required
def update_application_status(request, application_id):
    application = get_object_or_404(JobApplication, id=application_id)
    if request.method == 'POST':
        application.status = request.POST['status']
        application.selection_round = request.POST['selection_round']
        application.save()
        return redirect('job_applications')
    return render(request, 'job_applications.html')
