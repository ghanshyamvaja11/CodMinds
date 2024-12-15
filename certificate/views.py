from django.shortcuts import render
from .models import *
from django.views.decorators.csrf import csrf_exempt


def verify_certificate(request):
    certificate_code = None;
    if request.method == 'POST':
        certificate_code = request.POST.get('certificate_code')
        try:
            certificate = InternshipCertificate.objects.get(certificate_code=certificate_code)
            return render(request, 'verify_certificate.html', {'certificate': certificate, 'certificate_code': certificate_code})
        except InternshipCertificate.DoesNotExist:
            certificate = None
            return render(request, 'verify_certificate.html', {'certificate': certificate, 'certificate_code': certificate_code})
    return render(request, 'verify_certificate.html', {'certificate_code': certificate_code})

def verify_certificate_by_link(request, certificate_code):
    try:
        certificate = InternshipCertificate.objects.get(certificate_code=certificate_code)
    except InternshipCertificate.DoesNotExist:
        certificate = None

    return render(request, 'verify_cert_by_link.html', {'certificate': certificate, 'certificate_code': certificate_code})

def intern_certificate(request, certificate_code):
    certificate = InternshipCertificate.objects.get(certificate_code=certificate_code)

    context = {
        'recipient_name': certificate.recipient_name,
        'internship_field': certificate.internship_field,
        'project_name': certificate.project,
        'start_date': certificate.start_date,
        'end_date': certificate.end_date,
        'issued_at': certificate.issued_at,
        'certificate_code': certificate.certificate_code,
    }
    if request.method == "POST":
        pdf_file = request.FILES.get("certificate")
        if pdf_file:
            # Save file to media folder
            file_path = os.path.join(pdf_file.name)
            default_storage.save(file_path, ContentFile(pdf_file.read()))
            return JsonResponse({"success": "Certificate saved successfully!"})
        return JsonResponse({"error": "No file received!"}, status=400)
    return render(request, 'print_intern_certificate.html', context)

@csrf_exempt
def save_certificate(request):
    if request.method == "POST":
        pdf_file = request.FILES.get("certificate")
        if pdf_file:
            # Save file to media folder
            file_path = os.path.join("certificates", pdf_file.name)
            default_storage.save(file_path, ContentFile(pdf_file.read()))
            return JsonResponse({"success": "Certificate saved successfully!"})
        return JsonResponse({"error": "No file received!"}, status=400)
    return JsonResponse({"error": "Invalid request method!"}, status=405)