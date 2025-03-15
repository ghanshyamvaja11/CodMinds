from django.shortcuts import render, redirect
from .models import *
from django.contrib import messages
from django.contrib.messages import get_messages
from authority.models import InternshipProjects
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from carriers.models import *
import base64
import json
import re
import markdown2
import jwt
import black
from pygments.lexers import guess_lexer, get_lexer_by_name
from pygments.util import ClassNotFound
from difflib import unified_diff
import hashlib
import bcrypt
import scrypt
import argon2
import hmac
import urllib.parse
import requests
from django.middleware.csrf import get_token
import dns.resolver
from bs4 import BeautifulSoup


def clear_messages(request):
    storage = get_messages(request)
    for _ in storage:
        pass


def home(request):
    clear_messages(request)
    return render(request, 'index.html')


def about(request):
    clear_messages(request)
    return render(request, 'aboutus.html')


def services(request):
    clear_messages(request)
    return render(request, 'services.html')


def T_and_C(request):
    clear_messages(request)
    return render(request, 'T&C.html')


def privacy_policy(request):
    clear_messages(request)
    return render(request, 'privacy_policy.html')


def cancellation_refund_policies(request):
    clear_messages(request)
    return render(request, 'cancellation_refund_policies.html')


def contact(request):
    clear_messages(request)
    if request.method == 'POST':
        # Get form data
        name = request.POST.get('name')
        email = request.POST.get('email')
        subject = request.POST.get('subject')
        message = request.POST.get('message')

        # Save data to database
        contact_message = ContactForm(
            name=name, email=email, subject=subject, message=message)
        contact_message.save()

        # Success message
        messages.success(
            request, "Thank you for your message. We will get back to you soon.")
        return render(request, 'index.html')
    return render(request, 'contactus.html')


def internship_program(request):
    clear_messages(request)
    query = request.GET.get('search', '')
    field = request.GET.get('field', '')
    duration = request.GET.get('duration', '')

    internships = InternshipProjects.objects.all()

    if query:
        internships = internships.filter(title__icontains=query)
    if field:
        internships = internships.filter(field=field)
    if duration:
        internships = internships.filter(duration=duration)

    fields = InternshipProjects.get_unique_fields()

    return render(request, 'internship_program.html', {
        'internships': internships,
        'query': query,
        'field': field,
        'duration': duration,
        'fields': fields,
        'selected_field': field,
    })


def web_development(request):
    clear_messages(request)
    return render(request, 'web_development.html')


def software_development(request):
    clear_messages(request)
    return render(request, 'software_development.html')


def data_analytics(request):
    clear_messages(request)
    return render(request, 'data_analytics.html')


def error_404_view(request, exception=None):
    clear_messages(request)
    return render(request, '404.html', status=404)


def hire_us(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        email = request.POST.get('email')
        hiring_details = request.POST.get('details')

        # Save data to database
        hire_us_message = HireUs(
            name=name, email=email, hiring_details=hiring_details)
        hire_us_message.save()

        # Send email
        send_mail(
            subject=f"Hire Us Request sent",
            message=f"Name: {name}\nEmail: {email}\n\nHiring Details:\n{hiring_details} \nThank you for your request. We will get back to you soon.",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
        )

        messages.success(
            request, "Thank you for your request. We will get back to you soon.")
        return redirect(request.META.get('HTTP_REFERER', '/'))
    return redirect('home')


def carrier(request):
    clear_messages(request)
    try:
        if request.session.get('email'):
            user_email = request.session.get('email')
            vacancies = Vacancy.objects.filter(
                is_active=True, last_date_of_application__gte=timezone.now().date()
            ).order_by('-posted_date')

            applied_jobs = JobApplication.objects.filter(
                applicant_email=user_email).values_list('vacancy_id', flat=True)

            return render(request, 'carrier.html', {'vacancies': vacancies, 'applied_jobs': applied_jobs})
        else:
            vacancies = Vacancy.objects.filter(
                is_active=True, last_date_of_application__gte=timezone.now().date()
            ).order_by('-posted_date')

            return render(request, 'carrier.html', {'vacancies': vacancies, 'applied_jobs': []})
    except Exception as e:
        messages.error(
            request, "An unexpected error occurred. Please try again.")
        return render(request, 'carrier.html', {'vacancies': [], 'applied_jobs': []})


def tools_library(request):
    clear_messages(request)
    return render(request, 'tools_library.html')


def code_formatter(request):
    clear_messages(request)
    formatted_code = None
    error_message = None
    if request.method == 'POST':
        input_code = request.POST.get('input_code')
        language = request.POST.get('language')
        if input_code and language:
            try:
                if language in ['python', 'javascript', 'java', 'c', 'cpp', 'csharp', 'swift', 'kotlin', 'go', 'rust', 'html', 'css', 'typescript', 'php', 'ruby', 'dart', 'assembly', 'bash', 'powershell', 'perl', 'lua', 'r', 'julia', 'matlab', 'sql', 'plsql', 'graphql', 'haskell', 'lisp', 'scheme', 'clojure', 'fsharp', 'erlang', 'elixir', 'cobol', 'fortran', 'pascal', 'delphi', 'prolog']:
                    try:
                        formatted_code = black.format_str(
                            input_code, mode=black.Mode())
                    except black.InvalidInput as e:
                        error_message = f"Error formatting code: {str(e)}, select Right Language."
                else:
                    error_message = "Unsupported language selected."
            except Exception as e:
                error_message = f"Error formatting code: {str(e)}"
    return render(request, 'tools/Code&Utilities/code_formatter.html', {'formatted_code': formatted_code, 'error_message': error_message})


def text_diff_checker(request):
    clear_messages(request)
    diff_result = None
    if request.method == 'POST':
        input_diff = request.POST.get('input_diff')
        if input_diff:
            # Implement diff checking logic here
            diff_result = input_diff  # Placeholder for actual diff logic
    return render(request, 'tools/Code&Utilities/diff_checker.html', {'diff_result': diff_result})


def json_formatter_validator(request):
    clear_messages(request)
    formatted_json = None
    error_message = None
    if request.method == 'POST':
        input_json = request.POST.get('input_json')
        if input_json:
            try:
                parsed_json = json.loads(input_json)
                formatted_json = json.dumps(parsed_json, indent=4)
            except json.JSONDecodeError:
                error_message = "Invalid JSON"
    return render(request, 'tools/Code&Utilities/json_formatter_validator.html', {'formatted_json': formatted_json, 'error_message': error_message})


def markdown_to_html_converter(request):
    clear_messages(request)
    converted_html = None
    error_message = None
    if request.method == 'POST':
        input_markdown = request.POST.get('input_markdown')
        if input_markdown:
            try:
                converted_html = markdown2.markdown(input_markdown)
            except Exception as e:
                error_message = f"Error converting Markdown: {str(e)}"
    return render(request, 'tools/Code&Utilities/markdown_to_html_converter.html', {'converted_html': converted_html, 'error_message': error_message})


def diff_checker(request):
    clear_messages(request)
    diff_result = None
    if request.method == 'POST':
        input_diff1 = request.POST.get('input_diff1')
        input_diff2 = request.POST.get('input_diff2')
        if input_diff1 and input_diff2:
            diff = unified_diff(
                input_diff1.splitlines(),
                input_diff2.splitlines(),
                lineterm=''
            )
            diff_result = '\n'.join(diff)
    return render(request, 'tools/Code&Utilities/diff_checker.html', {'diff_result': diff_result})


def base64_encoder_decoder(request):
    clear_messages(request)
    base64_result = None
    if request.method == 'POST':
        input_text = request.POST.get('input_base64')
        if input_text:
            try:
                # Try to decode the input text
                base64_result = base64.b64decode(input_text).decode('utf-8')
            except Exception:
                # If decoding fails, encode the input text
                base64_result = base64.b64encode(
                    input_text.encode('utf-8')).decode('utf-8')
    return render(request, 'tools/Code&Utilities/base64_encoder_decoder.html', {'base64_result': base64_result})


def case_converter(request):
    clear_messages(request)
    converted_text = None
    if request.method == 'POST':
        input_text = request.POST.get('input_text')
        conversion_type = request.POST.get('conversion_type')
        if input_text and conversion_type:
            if conversion_type == 'uppercase':
                converted_text = input_text.upper()
            elif conversion_type == 'lowercase':
                converted_text = input_text.lower()
            elif conversion_type == 'titlecase':
                converted_text = input_text.title()
            elif conversion_type == 'sentencecase':
                converted_text = input_text.capitalize()
            elif conversion_type == 'camelcase':
                words = input_text.split()
                converted_text = words[0].lower(
                ) + ''.join(word.capitalize() for word in words[1:])
            elif conversion_type == 'pascalcase':
                converted_text = ''.join(word.capitalize()
                                         for word in input_text.split())
            elif conversion_type == 'snakecase':
                converted_text = '_'.join(input_text.lower().split())
            elif conversion_type == 'screamingsnakecase':
                converted_text = '_'.join(input_text.upper().split())
            elif conversion_type == 'kebabcase':
                converted_text = '-'.join(input_text.lower().split())
            elif conversion_type == 'cobolcase':
                converted_text = '-'.join(input_text.upper().split())
            elif conversion_type == 'traincase':
                converted_text = '-'.join(word.capitalize()
                                          for word in input_text.split())
            elif conversion_type == 'dotcase':
                converted_text = '.'.join(input_text.split())
            elif conversion_type == 'slashcase':
                converted_text = '/'.join(input_text.split())
            elif conversion_type == 'backslashcase':
                converted_text = '\\'.join(input_text.split())
            elif conversion_type == 'capitalizedcase':
                converted_text = ' '.join(word.capitalize()
                                          for word in input_text.split())
            elif conversion_type == 'inversecase':
                converted_text = ''.join(
                    char.lower() if char.isupper() else char.upper() for char in input_text)
            elif conversion_type == 'randomcase':
                import random
                converted_text = ''.join(char.upper() if random.choice(
                    [True, False]) else char.lower() for char in input_text)
    return render(request, 'tools/Code&Utilities/case_converter.html', {'converted_text': converted_text})


def string_hash_generator(request):
    clear_messages(request)
    hash_result = None
    error_message = None
    if request.method == 'POST':
        input_string = request.POST.get('input_string')
        algorithm = request.POST.get('algorithm')
        if input_string and algorithm:
            try:
                if algorithm == 'md5':
                    hash_result = hashlib.md5(
                        input_string.encode()).hexdigest()
                elif algorithm == 'sha1':
                    hash_result = hashlib.sha1(
                        input_string.encode()).hexdigest()
                elif algorithm == 'sha224':
                    hash_result = hashlib.sha224(
                        input_string.encode()).hexdigest()
                elif algorithm == 'sha256':
                    hash_result = hashlib.sha256(
                        input_string.encode()).hexdigest()
                elif algorithm == 'sha384':
                    hash_result = hashlib.sha384(
                        input_string.encode()).hexdigest()
                elif algorithm == 'sha512':
                    hash_result = hashlib.sha512(
                        input_string.encode()).hexdigest()
                elif algorithm == 'sha3_256':
                    hash_result = hashlib.sha3_256(
                        input_string.encode()).hexdigest()
                elif algorithm == 'sha3_512':
                    hash_result = hashlib.sha3_512(
                        input_string.encode()).hexdigest()
                elif algorithm == 'blake2b':
                    hash_result = hashlib.blake2b(
                        input_string.encode()).hexdigest()
                elif algorithm == 'blake2s':
                    hash_result = hashlib.blake2s(
                        input_string.encode()).hexdigest()
                elif algorithm == 'bcrypt':
                    hash_result = bcrypt.hashpw(
                        input_string.encode(), bcrypt.gensalt()).decode()
                elif algorithm == 'scrypt':
                    hash_result = scrypt.hash(
                        input_string.encode(), salt=b'salt').hex()
                elif algorithm == 'argon2':
                    hash_result = argon2.PasswordHasher().hash(input_string)
                elif algorithm == 'pbkdf2':
                    hash_result = hashlib.pbkdf2_hmac(
                        'sha256', input_string.encode(), b'salt', 100000).hex()
                elif algorithm == 'crc32':
                    hash_result = format(zlib.crc32(
                        input_string.encode()), '08x')
                elif algorithm == 'adler32':
                    hash_result = format(zlib.adler32(
                        input_string.encode()), '08x')
                # elif algorithm == 'murmurhash':
                #     hash_result = mmh3.hash(input_string)
                # elif algorithm == 'cityhash':
                #     hash_result = cityhash.CityHash64(input_string)
                # elif algorithm == 'farmhash':
                #     hash_result = farmhash.hash64(input_string)
                # elif algorithm == 'xxhash':
                #     hash_result = xxhash.xxh64(input_string).hexdigest()
                # elif algorithm == 'fnv':
                #     hash_result = fnv.hash(input_string)
                elif algorithm == 'siphash':
                    hash_result = hmac.new(
                        b'secret', input_string.encode(), hashlib.sha256).hexdigest()
                else:
                    error_message = "Unsupported algorithm selected."
            except Exception as e:
                error_message = f"Error generating hash: {str(e)}"
    return render(request, 'tools/Code&Utilities/string_hash_generator.html', {'hash_result': hash_result, 'error_message': error_message})


def minifier_beautifier(request):
    clear_messages(request)
    result_code = None
    if request.method == 'POST':
        input_code = request.POST.get('input_code')
        if input_code:
            # Implement minify/beautify logic here
            result_code = input_code  # Placeholder for actual minify/beautify logic
    return render(request, 'tools/Code&Utilities/minifier_beautifier.html', {'result_code': result_code})


def url_encoder_decoder(request):
    clear_messages(request)
    url_result = None
    if request.method == 'POST':
        input_url = request.POST.get('input_url')
        if input_url:
            try:
                # Try to decode the input URL
                url_result = urllib.parse.unquote(input_url)
            except Exception:
                # If decoding fails, encode the input URL
                url_result = urllib.parse.quote(input_url)
    return render(request, 'tools/Code&Utilities/url_encoder_decoder.html', {'url_result': url_result})


def jwt_decoder_generator(request):
    clear_messages(request)
    jwt_result = None
    error_message = None
    if request.method == 'POST':
        input_jwt = request.POST.get('input_jwt')
        payload = request.POST.get('payload')
        secret = request.POST.get('secret')
        if input_jwt:
            try:
                # Decode JWT
                jwt_result = jwt.decode(
                    input_jwt, options={"verify_signature": False})
                jwt_result = json.dumps(jwt_result, indent=4)
            except jwt.DecodeError:
                error_message = "Invalid JWT"
        elif payload and secret:
            try:
                # Generate JWT
                payload_dict = json.loads(payload)
                jwt_result = jwt.encode(
                    payload_dict, secret, algorithm="HS256")
            except Exception as e:
                error_message = f"Error generating JWT: {str(e)}"
    return render(request, 'tools/Code&Utilities/jwt_decoder_generator.html', {'jwt_result': jwt_result, 'error_message': error_message})


def regex_tester(request):
    clear_messages(request)
    regex_result = None
    error_message = None
    if request.method == 'POST':
        input_regex = request.POST.get('input_regex')
        input_text = request.POST.get('input_text')
        if input_regex and input_text:
            try:
                # Test regex
                pattern = re.compile(input_regex)
                matches = pattern.findall(input_text)
                error_message = '\n'.join(
                    matches) if matches else "No matches found"
            except re.error as e:
                error_message = f"Invalid Regex: {str(e)}"
    return render(request, 'tools/Code&Utilities/regex_tester.html', {'regex_result': regex_result, 'error_message': error_message})


def api_tester(request):
    clear_messages(request)
    api_response = None
    status_code = None
    status_code_color = None
    status_code_message = None
    error_message = None

    if request.method == 'POST':
        api_url = request.POST.get('api_url')
        request_method = request.POST.get('request_method')
        request_headers = request.POST.get('request_headers')
        request_body = request.POST.get('request_body')

        headers = {}
        if request_headers:
            try:
                headers = json.loads(request_headers)
            except json.JSONDecodeError:
                error_message = "Invalid JSON format for headers."

        data = {}
        if request_body:
            try:
                data = json.loads(request_body)
            except json.JSONDecodeError:
                error_message = "Invalid JSON format for body."

        if not error_message:
            try:
                csrf_token = get_token(request)
                headers['X-CSRFToken'] = csrf_token
                response = requests.request(
                    method=request_method,
                    url=api_url,
                    headers=headers,
                    json=data
                )
                api_response = response.text
                status_code = response.status_code
                status_code_message = response.reason
                if 200 <= status_code < 300:
                    status_code_color = "green"
                elif 400 <= status_code < 500:
                    status_code_color = "orange"
                elif 500 <= status_code < 600:
                    status_code_color = "red"
                else:
                    status_code_color = "black"
            except requests.RequestException as e:
                error_message = f"Request failed: {str(e)}"

    return render(request, 'tools/API&WebAnalysis/api_tester.html', {
        'api_response': api_response,
        'status_code': status_code,
        'status_code_color': status_code_color,
        'status_code_message': status_code_message,
        'error_message': error_message
    })


def network_analyzer(request):
    clear_messages(request)
    analysis_result = None
    error_message = None
    if request.method == 'POST':
        network_input = request.POST.get('network_input')
        if network_input:
            try:
                # Example network analysis logic: counting IP addresses
                ip_addresses = re.findall(
                    r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', network_input)
                ip_count = len(ip_addresses)
                analysis_result = f"Found {ip_count} IP addresses:\n" + \
                    '\n'.join(ip_addresses)
            except Exception as e:
                error_message = f"Error analyzing network data: {str(e)}"
    return render(request, 'tools/API&WebAnalysis/network_analyzer.html', {'analysis_result': analysis_result, 'error_message': error_message})


def rest_api_tester(request):
    clear_messages(request)
    return render(request, 'tools/API&WebAnalysis/rest_api_tester.html')


def http_headers_inspector(request):
    if request.method == 'POST':
        url = request.POST.get('url')
        try:
            response = requests.head(url)
            headers = dict(response.headers)
            formatted_headers = json.dumps(headers, indent=2)
            return render(request, 'Tools/API&WebAnalysis/http_headers_inspector.html', {'headers': formatted_headers})
        except requests.RequestException as e:
            return render(request, 'Tools/API&WebAnalysis/http_headers_inspector.html', {'error_message': str(e)})
    return render(request, 'Tools/API&WebAnalysis/http_headers_inspector.html')


def dns_lookup_tool(request):
    clear_messages(request)
    dns_records = None
    error_message = None
    if request.method == 'POST':
        domain = request.POST.get('domain')
        if domain:
            try:
                dns_records = {}
                for record_type in ['A', 'AAAA', 'MX', 'NS', 'CNAME', 'TXT', 'SOA']:
                    try:
                        result = dns.resolver.resolve(domain, record_type)
                        dns_records[record_type] = '\n'.join(
                            [str(rdata) for rdata in result])
                    except dns.resolver.NoAnswer:
                        dns_records[record_type] = 'No record found'
            except Exception as e:
                error_message = f"Error resolving domain: {str(e)}"
    return render(request, 'tools/API&WebAnalysis/dns_lookup_tool.html', {'dns_records': dns_records, 'error_message': error_message})


def whois_lookup(request):
    clear_messages(request)
    return render(request, 'tools/API&WebAnalysis/whois_lookup.html')


def ip_address_lookup(request):
    clear_messages(request)
    ip_info = None
    error_message = None
    if request.method == 'POST':
        ip_address = request.POST.get('ip_address')
        if ip_address:
            try:
                response = requests.get(f"https://ipinfo.io/{ip_address}/json")
                if response.status_code == 200:
                    ip_info = json.dumps(response.json(), indent=4)
                else:
                    error_message = "Error fetching IP information."
            except requests.RequestException as e:
                error_message = f"Error fetching IP information: {str(e)}"
    return render(request, 'tools/API&WebAnalysis/ip_address_lookup.html', {'ip_info': ip_info, 'error_message': error_message})


def port_scanner(request):
    clear_messages(request)
    return render(request, 'tools/API&WebAnalysis/port_scanner.html')


def website_screenshot_api(request):
    clear_messages(request)
    return render(request, 'tools/API&WebAnalysis/website_screenshot_api.html')


def meta_tag_analyzer(request):
    clear_messages(request)
    meta_tags = None
    error_message = None
    if request.method == 'POST':
        website_url = request.POST.get('website_url')
        if website_url:
            try:
                response = requests.get(website_url)
                soup = BeautifulSoup(response.content, 'html.parser')
                meta_tags = '\n'.join(str(tag)
                                      for tag in soup.find_all('meta'))
            except requests.RequestException as e:
                error_message = f"Error fetching URL: {str(e)}"
            except Exception as e:
                error_message = f"Error parsing HTML: {str(e)}"
    return render(request, 'tools/API&WebAnalysis/meta_tag_analyzer.html', {'meta_tags': meta_tags, 'error_message': error_message})


def robots_txt_sitemap_validator(request):
    clear_messages(request)
    return render(request, 'tools/API&WebAnalysis/robots_txt_sitemap_validator.html')


def ssl_certificate_checker(request):
    clear_messages(request)
    return render(request, 'tools/API&WebAnalysis/ssl_certificate_checker.html')
