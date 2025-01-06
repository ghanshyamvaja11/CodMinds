from django.shortcuts import redirect
from django.shortcuts import render


class Force404Middleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path == '/page-not-found/':
            return render(request, '404.html')
        response = self.get_response(request)
        if response.status_code == 404:
            return redirect('error_404_view')
        if response.status_code == 400:
            return redirect('error_404_view')
        return response