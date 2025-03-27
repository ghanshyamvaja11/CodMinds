from collections import defaultdict
from django.contrib.messages import get_messages, add_message, constants as message_constants
from django.shortcuts import render
import html
import math
import time
import zlib
from django.shortcuts import render, redirect
from django.http import HttpResponse
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
import string
import uuid
import random
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
import socket
import concurrent.futures
import ssl
import datetime
import os
import whois  # Add this import
import yaml  # Add this import
import barcode
from barcode.writer import ImageWriter
import base64
import io
# from selenium import webdriver
# from selenium.webdriver.chrome.options import Options
import json
from Crypto.Cipher import AES, DES, DES3, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
import csv
import io
import xml.etree.ElementTree as ET
from PIL import Image
from colorthief import ColorThief
from django.core.files.storage import default_storage  # new import
from django.core.files.base import ContentFile         # new import
import io
import uuid
from PIL import Image
from PIL.ExifTags import TAGS
import qrcode
from pyzbar.pyzbar import decode  # new import for QR code decoding


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


def subscribe(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        if email:
            try:
                # Check if email already exists in the database
                subscriber = Subscribe.objects.get(email=email)
                messages.warning(
                    request, "Email already exists in our database. Please try another one.")
            except Subscribe.DoesNotExist:
                # Save new subscriber to the database
                subscriber = Subscribe(email=email)
                subscriber.save()
                send_mail(
                    subject="subscribe confirmation",
                    message="Thank you for subscribing to our newsletter. You will receive updates soon.",
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[email]
                )
                messages.success(
                    request, "Thank you for subscribing to our newsletter. You will receive updates soon.")
        else:
            messages.error(
                request, "Please enter a valid email address.")
    return redirect('tools_library')


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
    return render(request, 'Tools/Code&Utilities/code_formatter.html', {'formatted_code': formatted_code, 'error_message': error_message})


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
    return render(request, 'Tools/Code&Utilities/json_formatter_validator.html', {'formatted_json': formatted_json, 'error_message': error_message})


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
    return render(request, 'Tools/Code&Utilities/base64_encoder_decoder.html', {'base64_result': base64_result})


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
                converted_text = ''.join(char.upper() if random.choice(
                    [True, False]) else char.lower() for char in input_text)
    return render(request, 'Tools/Code&Utilities/case_converter.html', {'converted_text': converted_text})


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
                    hash_result = hashlib.pbdf2_hmac(
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
    return render(request, 'Tools/Code&Utilities/string_hash_generator.html', {'hash_result': hash_result, 'error_message': error_message})


def url_encoder_decoder(request):
    clear_messages(request)
    url_result = None
    error_message = None
    if request.method == 'POST':
        input_url = request.POST.get('input_url')
        action = request.POST.get('action')
        if input_url and action:
            try:
                if action == 'encode':
                    # Encode the URL with base64
                    url_result = base64.urlsafe_b64encode(
                        input_url.encode('utf-8')).decode('utf-8')
                elif action == 'decode':
                    url_result = base64.urlsafe_b64decode(
                        input_url.encode('utf-8')).decode('utf-8')
                else:
                    error_message = "Invalid action selected."
            except Exception as e:
                error_message = f"Error processing URL: {str(e)}"
    return render(request, 'Tools/API&WebAnalysis/url_encoder_decoder.html', {'url_result': url_result, 'error_message': error_message})


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
    return render(request, 'Tools/Code&Utilities/jwt_decoder_generator.html', {'jwt_result': jwt_result, 'error_message': error_message})


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
    return render(request, 'Tools/Code&Utilities/regex_tester.html', {'regex_result': regex_result, 'error_message': error_message})


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

    return render(request, 'Tools/API&WebAnalysis/api_tester.html', {
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
    return render(request, 'Tools/API&WebAnalysis/network_analyzer.html', {'analysis_result': analysis_result, 'error_message': error_message})


def rest_api_tester(request):
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

    return render(request, 'Tools/API&WebAnalysis/rest_api_tester.html', {
        'api_response': api_response,
        'status_code': status_code,
        'status_code_color': status_code_color,
        'status_code_message': status_code_message,
        'error_message': error_message
    })


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
    return render(request, 'Tools/API&WebAnalysis/dns_lookup_tool.html', {'dns_records': dns_records, 'error_message': error_message})


def whois_lookup(request):
    clear_messages(request)
    whois_info = None
    error_message = None
    if request.method == 'POST':
        domain = request.POST.get('domain')
        if domain:
            try:
                w = whois.whois(domain)
                whois_info = json.dumps(w, indent=4, default=str)
            except Exception as e:
                error_message = f"Error retrieving WHOIS information: {str(e)}"
    return render(request, 'Tools/API&WebAnalysis/whois_lookup.html', {'whois_info': whois_info, 'error_message': error_message})


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
    return render(request, 'Tools/API&WebAnalysis/ip_address_lookup.html', {'ip_info': ip_info, 'error_message': error_message})


def port_scanner(request):
    clear_messages(request)
    scan_result = None

    def check_port(ip, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)
        result = sock.connect_ex((ip, port))
        sock.close()
        return port if result == 0 else None

    if request.method == 'POST':
        target_ip = request.POST.get('target_ip')
        if target_ip:
            open_ports = []
            with concurrent.futures.ThreadPoolExecutor() as executor:
                futures = [executor.submit(check_port, target_ip, p)
                           for p in range(1, 1025)]
                for future in concurrent.futures.as_completed(futures):
                    port = future.result()
                    if port:
                        open_ports.append(port)
            scan_result = open_ports if open_ports else "No open ports found."
    return render(request, 'Tools/API&WebAnalysis/port_scanner.html', {'scan_result': scan_result})


def website_screenshot_api(request):
    clear_messages(request)
    screenshot = None
    html_content = None
    error_message = None

    if request.method == 'POST':
        website_url = request.POST.get('website_url')
        if website_url:
            try:
                options = Options()
                options.headless = True
                options.add_argument("--start-maximized")
                options.add_argument("--disable-infobars")
                options.add_argument("--disable-gpu")
                options.add_argument("--disable-dev-shm-usage")
                options.add_argument("--no-sandbox")

                driver = webdriver.Chrome(options=options)
                driver.get(website_url)

                # Wait until the page is fully loaded
                WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((By.TAG_NAME, "body"))
                )

                # Get total scroll height and width
                total_width = driver.execute_script(
                    "return document.body.scrollWidth")
                total_height = driver.execute_script(
                    "return document.body.scrollHeight")

                # Set window size to capture the entire page
                driver.set_window_size(total_width, total_height)

                # Ensure page is fully scrolled to capture everything
                driver.execute_script("window.scrollTo(0, 0);")

                # Capture full-page screenshot
                screenshot = driver.get_screenshot_as_base64()

                # Capture full HTML source
                html_content = driver.page_source

                driver.quit()

                screenshot = f"data:image/png;base64,{screenshot}"

            except Exception as e:
                error_message = f"Error capturing screenshot: {str(e)}"

    return render(request, 'Tools/API&WebAnalysis/website_screenshot_api.html', {
        'screenshot': screenshot,
        'html_content': html_content,
        'error_message': error_message
    })


def download_screenshot(request):
    if request.method == 'POST':
        screenshot_data = request.POST.get('screenshot_data')
        if screenshot_data:
            screenshot_data = screenshot_data.split(",")[1]
            screenshot_bytes = base64.b64decode(screenshot_data)
            response = HttpResponse(screenshot_bytes, content_type='image/png')
            response['Content-Disposition'] = 'attachment; filename="full_page_screenshot.png"'
            return response
    return redirect('website_screenshot_api')


def download_full_html(request):
    if request.method == 'POST':
        html_content = request.POST.get('html_content')
        if html_content:
            response = HttpResponse(html_content, content_type='text/html')
            response['Content-Disposition'] = 'attachment; filename="full_page.html"'
            return response
    return redirect('website_screenshot_api')


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
    return render(request, 'Tools/API&WebAnalysis/meta_tag_analyzer.html', {'meta_tags': meta_tags, 'error_message': error_message})


def robots_txt_sitemap_validator(request):
    clear_messages(request)
    return render(request, 'Tools/API&WebAnalysis/robots_txt_sitemap_validator.html')


def ssl_certificate_checker(request):
    clear_messages(request)
    ssl_info = None
    error_message = None
    if request.method == 'POST':
        website_url = request.POST.get('website_url')
        if website_url:
            try:
                hostname = website_url.replace(
                    'https://', '').replace('http://', '').strip('/')
                context = ssl.create_default_context()
                conn = socket.create_connection((hostname, 443), timeout=5)
                sock = context.wrap_socket(conn, server_hostname=hostname)
                cert = sock.getpeercert()
                sock.close()
                subject = dict(x[0] for x in cert["subject"])
                issuer = dict(x[0] for x in cert["issuer"])
                not_before = cert["notBefore"]
                not_after = cert["notAfter"]
                ssl_info = f"Subject: {subject}\nIssuer: {issuer}\nValid From: {not_before}\nValid Until: {not_after}"
            except Exception as e:
                error_message = f"Error retrieving SSL certificate: {str(e)}"

    return render(request, 'Tools/API&WebAnalysis/ssl_certificate_checker.html', {
        'ssl_info': ssl_info,
        'error_message': error_message
    })


# Security and Authentication
def password_generator(request):
    clear_messages(request)
    generated_password = None
    if request.method == 'POST':
        length = int(request.POST.get('length', 12))
        include_uppercase = 'uppercase' in request.POST
        include_lowercase = 'lowercase' in request.POST
        include_digits = 'digits' in request.POST
        include_punctuation = 'punctuation' in request.POST

        characters = ''
        if include_uppercase:
            characters += string.ascii_uppercase
        if include_lowercase:
            characters += string.ascii_lowercase
        if include_digits:
            characters += string.digits
        if include_punctuation:
            characters += string.punctuation

        if characters:
            generated_password = ''.join(
                random.choice(characters) for _ in range(length))
        else:
            generated_password = 'Please select at least one character type.'

    return render(request, 'Tools/Security/password_generator.html', {'generated_password': generated_password})


def uuid_generator(request):
    clear_messages(request)
    generated_uuid = None
    if request.method == 'POST':
        generated_uuid = str(uuid.uuid4())
    return render(request, 'Tools/Security/uuid_generator.html', {'generated_uuid': generated_uuid})


def clear_messages(request):
    list(get_messages(request))  # Clear any previous messages


def xss_vulnerability_tester(request):
    clear_messages(request)
    xss_result = None
    error_message = None
    progress = 0
    vulnerability_level = "No risk"
    vulnerability_color = "#33cc33"  # green
    risk_percentage = 0

    if request.method == 'POST':
        input_text = request.POST.get('input_text', '')

        if input_text.strip():
            progress = 50  # Initial progress
            detected_xss = False  # Flag for XSS detection

            # 1. Check for encoded XSS attempts
            # Decode any encoded characters (e.g., `&lt;script&gt;` -> `<script>`)
            decoded_input = html.unescape(input_text)

            # 2. Check for dangerous HTML elements
            soup = BeautifulSoup(decoded_input, "html.parser")
            dangerous_tags = ['script', 'iframe', 'embed', 'object', 'link', 'style', 'meta', 'form',
                              'input', 'textarea', 'button', 'select', 'option', 'applet', 'marquee', 'blink']
            found_tags = [tag.name for tag in soup.find_all(dangerous_tags)]

            # 3. Check for JavaScript event handlers (onmouseover, onload, etc.)
            event_handlers = re.findall(
                r'on\w+\s*=\s*["\'].*?["\']', decoded_input, re.IGNORECASE)

            # 4. Check if there's any JavaScript execution attempt
            js_execution_patterns = re.findall(
                r'javascript\s*:\s*.*', decoded_input, re.IGNORECASE)

            # 5. Compare sanitized vs unsanitized
            # Escaping dangerous characters
            sanitized_input = html.escape(decoded_input)
            if sanitized_input != decoded_input:
                detected_xss = True

            # 6. Risk Calculation
            total_issues = len(found_tags) + \
                len(event_handlers) + len(js_execution_patterns)
            if detected_xss or total_issues > 0:
                xss_result = "Potential XSS vulnerability detected."
                risk_percentage = min(
                    total_issues * 20, 100)  # Example: 5 issues = 100%

                if risk_percentage > 70:
                    vulnerability_level = "High risk"
                    vulnerability_color = "#ff4d4d"  # red
                elif risk_percentage > 30:
                    vulnerability_level = "Moderate risk"
                    vulnerability_color = "#ffa500"  # orange
                else:
                    vulnerability_level = "Low risk"
                    vulnerability_color = "#33cc33"  # green

                progress = 100
            else:
                xss_result = "No XSS vulnerability detected."
                vulnerability_level = "No risk"
                vulnerability_color = "#33cc33"  # green
                progress = 100
        else:
            error_message = "Please provide input text to test."

    return render(request, 'Tools/Security/xss_vulnerability_tester.html', {
        'xss_result': xss_result,
        'error_message': error_message,
        'progress': progress,
        'vulnerability_level': vulnerability_level,
        'vulnerability_color': vulnerability_color,
        'risk_percentage': risk_percentage
    })


def clear_messages(request):
    storage = messages.get_messages(request)
    storage.used = True


def clear_messages(request):
    request.session.pop('_messages', None)


def sql_injection_tester(request):
    clear_messages(request)
    sql_result = None
    risk_percentage = 0
    risk_level = "Low risk"

    if request.method == 'POST':
        input_query = request.POST.get('input_query', '').strip()

        # Advanced SQL Injection Detection
        sql_keywords = [
            "SELECT", "UNION", "DROP", "INSERT", "UPDATE", "DELETE", "ALTER", "EXEC", "MERGE",
            "DECLARE", "CAST", "NVARCHAR", "CHAR", "CONVERT", "INFORMATION_SCHEMA", "SYSOBJECTS"
        ]
        attack_patterns = [
            r"(--|#|/\*)",  # SQL comments
            r"\b(OR|AND)\b.*?[=<>]",  # Boolean-based SQLi
            r"\bUNION\b.*?\bSELECT\b",  # UNION-based SQLi
            r"\bSLEEP\(\d+\)|\bWAITFOR DELAY\b",  # Time-based SQLi
            r"\bCASE\b.*?\bWHEN\b.*?\bTHEN\b",  # Conditional injection
            r"\bLIKE\b.*?['\"]%.*?['\"]",  # Pattern matching attack
            r"XP_CMDSHELL|EXEC|EXECUTE",  # OS command execution
            r"CONCAT\(.*?'.*?'\)",  # String concatenation attacks
        ]

        # Detect dangerous keywords and attack patterns
        keyword_count = sum(
            1 for kw in sql_keywords if kw in input_query.upper())
        pattern_matches = [pattern for pattern in attack_patterns if re.search(
            pattern, input_query, re.IGNORECASE)]
        suspicious_chars = ['=', '--', ';', "'", '"']
        suspicious_count = sum(input_query.count(char)
                               for char in suspicious_chars)

        # Risk Scoring System
        risk_score = keyword_count * 10 + \
            suspicious_count * 5 + len(pattern_matches) * 15
        if len(input_query) > 100:
            risk_score += 20  # Longer queries are riskier

        # Risk Level Classification
        if risk_score > 70:
            risk_level = "Critical risk"
        elif risk_score > 50:
            risk_level = "High risk"
        elif risk_score > 30:
            risk_level = "Moderate risk"
        else:
            risk_level = "Low risk"
        risk_percentage = min(risk_score, 100)

        # Final output
        sql_result = (
            f"Input Query: {input_query}\n"
            f"Detected SQL Keywords: {keyword_count}\n"
            f"Suspicious Characters Count: {suspicious_count}\n"
            f"Matched Attack Patterns: {len(pattern_matches)}\n"
            f"Risk Score: {risk_score} ({risk_level})\n"
        )

    return render(request, 'Tools/Security/sql_injection_tester.html', {
        'sql_result': sql_result,
        'risk_percentage': risk_percentage,
        'risk_level': risk_level
    })


def jwt_expiry_checker(request):
    clear_messages(request)
    jwt_result = None
    error_message = None
    if request.method == 'POST':
        input_jwt = request.POST.get('input_jwt')
        if input_jwt:
            try:
                decoded_jwt = jwt.decode(
                    input_jwt, options={"verify_signature": False})
                expiry = decoded_jwt.get('exp')
                if expiry:
                    expiry_date = datetime.datetime.fromtimestamp(expiry)
                    jwt_result = f"JWT expires on: {expiry_date}"
                else:
                    jwt_result = "No expiry date found in JWT"
            except jwt.DecodeError:
                error_message = "Invalid JWT"
    return render(request, 'Tools/Security/jwt_expiry_checker.html', {'jwt_result': jwt_result, 'error_message': error_message})


def password_strength_checker(request):
    strength_result = None
    strength_color = None
    score = 1  # Default minimum score

    if request.method == 'POST':
        password = request.POST.get('password', '').strip()

        # Common weak passwords
        COMMON_PASSWORDS = {"123456", "password", "12345678",
                            "qwerty", "abc123", "admin", "letmein", "welcome"}

        if password.lower() in COMMON_PASSWORDS:
            strength_result = "Very Weak"
            strength_color = "#ff1a1a"  # Dark Red
            score = 1
        else:
            # Base Score Calculation (Max: 4)
            local_score = 1  # Start at minimum (1)

            # Character set determination
            charset_size = 0
            if re.search(r"[a-z]", password):
                charset_size += 26
            if re.search(r"[A-Z]", password):
                charset_size += 26
            if re.search(r"[0-9]", password):
                charset_size += 10
            if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
                charset_size += 32

            # Entropy Calculation
            entropy = len(password) * \
                math.log2(charset_size) if charset_size > 0 else 0

            # Strength Levels Based on Rules
            has_lower = bool(re.search(r"[a-z]", password))
            has_upper = bool(re.search(r"[A-Z]", password))
            has_digit = bool(re.search(r"[0-9]", password))
            has_special = bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password))
            length_ok = len(password) >= 8

            if length_ok and (has_lower + has_upper + has_digit + has_special) >= 2:
                local_score = 2
            if length_ok and has_lower and has_upper and has_digit and has_special:
                local_score = 3
            if entropy > 40 and len(password) >= 12:
                local_score = 4

            # Ensure score stays between 1-4
            score = max(1, min(local_score, 4))

            # Strength Classification
            if score == 1:
                strength_result = "Very Weak"
                strength_color = "#ff4d4d"  # Red
            elif score == 2:
                strength_result = "Weak"
                strength_color = "#ff9933"  # Orange
            elif score == 3:
                strength_result = "Moderate"
                strength_color = "#ffd700"  # Yellow
            elif score == 4:
                strength_result = "Strong"
                strength_color = "#33cc33"  # Green

    return render(request, 'Tools/Security/password_strength_checker.html', {
        'strength_result': strength_result,
        'strength_color': strength_color,
        'score': score
    })


def clean_numeric(value):
    """
    Cleans numeric values by removing currency symbols and formatting correctly.
    Handles:
    - `"$2,000"` → `"2000"`
    - `"€2.5"` → `"2.5"`
    - `"2,500.00"` → `"2500.00"`
    """
    if value:
        value = value.strip()
        # If value contains numbers with optional symbols
        if re.match(r'^[^\d]*[\d,\.]+$', value):
            # Remove non-numeric except comma/period
            cleaned = re.sub(r'[^\d,\.]', '', value)
            cleaned = cleaned.replace(',', '')  # Remove thousands separator
            try:
                num = float(cleaned)
                # Keep decimals where needed
                return num if "." in cleaned else int(num)
            except ValueError:
                return value
    return value


def detect_delimiter(csv_text):
    """
    Auto-detects the delimiter used in the CSV data.
    """
    try:
        sample = csv_text.split("\n", 3)
        sample_text = "\n".join(sample)
        sniffer = csv.Sniffer()
        dialect = sniffer.sniff(sample_text)
        return dialect.delimiter
    except Exception:
        return ','


def csv_to_json_converter(request):
    """
    Converts CSV data (from file or pasted text) into JSON format.
    """
    clear_messages(request)
    json_data = None

    if request.method == 'POST':
        input_method = request.POST.get('input_method')
        csv_file = request.FILES.get('csv_file')
        csv_text = request.POST.get('csv_text', '')

        if input_method == 'upload' and csv_file:
            try:
                if not csv_file.name.endswith('.csv'):
                    messages.error(
                        request, "Invalid file type. Please upload a CSV file.")
                    return redirect('csv_to_json_converter')

                file_data = csv_file.read().decode('utf-8', errors='replace').strip()
                delimiter = detect_delimiter(file_data)

            except Exception as e:
                messages.error(request, f"Error reading file: {str(e)}")
                return redirect('csv_to_json_converter')

        elif input_method == 'paste' and csv_text.strip():
            try:
                if csv_text.startswith("{") or csv_text.startswith("["):
                    raise ValueError(
                        "Invalid input: Detected JSON format instead of CSV.")
                csv_text = csv_text.strip()
                delimiter = detect_delimiter(csv_text)

            except ValueError as e:
                messages.error(request, str(e))
                return redirect('csv_to_json_converter')

            except Exception:
                messages.error(
                    request, "Invalid CSV format. Please check your input.")
                return redirect('csv_to_json_converter')

        else:
            messages.error(request, "No valid input provided.")
            return redirect('csv_to_json_converter')

        try:
            csv_source = file_data if input_method == 'upload' else csv_text
            reader = csv.reader(io.StringIO(csv_source), delimiter=delimiter)
            rows = list(reader)

            if len(rows) < 2:
                messages.error(
                    request, "Invalid CSV format. Ensure at least two rows (header + data).")
                return redirect('csv_to_json_converter')

            headers = [col.strip()
                       for col in rows[0]]  # Split headers properly
            json_list = []

            for row in rows[1:]:
                if len(row) != len(headers):
                    continue  # Skip rows with inconsistent column counts.
                clean_row = {}
                for i in range(len(headers)):
                    key = headers[i]
                    value = row[i]
                    clean_row[key] = clean_numeric(
                        value)  # Apply numeric cleaning
                json_list.append(clean_row)

            json_data = json.dumps(json_list, indent=4)
        except Exception as e:
            messages.error(request, f"Error processing CSV: {str(e)}")
            return redirect('csv_to_json_converter')

    return render(request, 'Tools/DataConversion/csv_to_json_converter.html', {'json_data': json_data})


def json_to_csv_converter(request):
    messages.get_messages(request)  # Clear old messages
    csv_data = None

    if request.method == 'POST':
        input_method = request.POST.get('input_method')
        json_file = request.FILES.get('json_file')
        json_text = request.POST.get('json_text', '').strip()

        try:
            # Step 1: Load JSON Data
            if input_method == 'upload' and json_file:
                if not json_file.name.endswith('.json'):
                    messages.error(
                        request, "Invalid file type. Please upload a JSON file.")
                    return redirect('json_to_csv_converter')

                file_data = json_file.read().decode('utf-8', errors='replace').strip()
                json_content = json.loads(file_data)

            elif input_method == 'paste' and json_text:
                json_content = json.loads(json_text)
            else:
                messages.error(request, "Invalid input method or empty input.")
                return redirect('json_to_csv_converter')

            # Step 2: Extract rows from nested JSON
            def flatten_dict(d, parent_key='', sep='_'):
                """ Recursively flatten a dictionary """
                items = {}
                for k, v in d.items():
                    new_key = f"{parent_key}{sep}{k}" if parent_key else k
                    if isinstance(v, dict):
                        items.update(flatten_dict(v, new_key, sep=sep))
                    else:
                        items[new_key] = v
                return items

            def extract_rows(data):
                """
                Extracts rows from JSON.
                If a dictionary contains a key with a list of dicts (e.g. 'person'),
                return each dict in the list as a row.
                Otherwise, flatten the dict.
                """
                rows = []
                if isinstance(data, list):
                    for item in data:
                        rows.extend(extract_rows(item))
                    return rows
                elif isinstance(data, dict):
                    # Check if this dict has a nested dict that holds a list of rows.
                    # For example: { "people": { "person": [ {..}, {..} ] } }
                    if len(data) == 1:
                        key = next(iter(data))
                        value = data[key]
                        if isinstance(value, dict):
                            for subkey, subval in value.items():
                                if isinstance(subval, list) and all(isinstance(x, dict) for x in subval):
                                    # Return each record from the nested list (flattened)
                                    return [flatten_dict(record, parent_key='') for record in subval]
                    # Otherwise, simply flatten this dict and return it as one row.
                    return [flatten_dict(data, parent_key='')]
                return []

            all_rows = extract_rows(json_content)

            if not all_rows:
                messages.error(request, "Invalid JSON structure.")
                return redirect('json_to_csv_converter')

            # Step 3: Generate CSV output
            output = io.StringIO()
            # Use all keys across rows (sorted for consistency)
            fieldnames = sorted(
                {key for row in all_rows for key in row.keys()})
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(all_rows)
            csv_data = output.getvalue()

        except json.JSONDecodeError:
            messages.error(
                request, "Invalid JSON format. Please check your input.")
        except Exception as e:
            messages.error(request, f"Error converting JSON to CSV: {str(e)}")

    return render(request, 'Tools/DataConversion/json_to_csv_converter.html', {'csv_data': csv_data})


def html_table_to_json_converter(request):
    clear_messages(request)
    json_data = None
    error_message = None

    if request.method == 'POST':
        html_content = request.POST.get('html_content', '').strip()
        html_file = request.FILES.get('html_file')

        if html_file:
            try:
                if not html_file.name.endswith('.html'):
                    raise ValueError(
                        "Invalid file type. Please upload an HTML file.")
                file_data = html_file.read().decode('utf-8', errors='replace').strip()
                soup = BeautifulSoup(file_data, 'html.parser')
            except Exception as e:
                error_message = f"Error reading HTML file: {str(e)}"
        elif html_content:
            try:
                soup = BeautifulSoup(html_content, 'html.parser')
            except Exception as e:
                error_message = f"Error parsing HTML content: {str(e)}"
        else:
            error_message = "Please provide HTML content or upload an HTML file."

        if not error_message:
            try:
                table = soup.find('table')

                if not table:
                    raise ValueError(
                        "No table found in the provided HTML content.")

                headers = [th.get_text(strip=True)
                           for th in table.find_all('th')]
                if not headers:
                    raise ValueError("No headers found in the table.")

                rows = []
                for tr in table.find_all('tr')[1:]:
                    cells = tr.find_all(['td', 'th'])
                    if len(cells) != len(headers):
                        raise ValueError(
                            "Row length does not match header length.")
                    row = {headers[i]: cells[i].get_text(
                        strip=True) for i in range(len(headers))}
                    rows.append(row)

                json_data = json.dumps(rows, indent=4)
            except Exception as e:
                error_message = f"Error converting HTML table: {str(e)}"

    return render(request, 'Tools/DataConversion/html_table_to_json_converter.html', {
        'json_data': json_data,
        'error_message': error_message
    })


def ET_to_dict(node):
    """
    Recursively converts an ElementTree node into a dictionary.
    If the node has no children, returns its text.
    Otherwise, each child is processed and if a tag appears multiple times,
    a list is created.
    """
    # Base case: if no children, return the text value (stripped) or empty string
    if not list(node):
        return node.text.strip() if node.text else ""

    result = {}
    for child in node:
        child_dict = ET_to_dict(child)
        tag = child.tag
        if tag in result:
            # If key exists, ensure it's a list
            if isinstance(result[tag], list):
                result[tag].append(child_dict)
            else:
                result[tag] = [result[tag], child_dict]
        else:
            result[tag] = child_dict

    # Include node attributes (prefixing with '@' to distinguish)
    if node.attrib:
        for key, value in node.attrib.items():
            result[f"@{key}"] = value

    return result


def xml_to_json_converter(request):
    # Clear previous messages if applicable
    json_data = None

    if request.method == 'POST':
        input_method = request.POST.get('input_method')
        xml_file = request.FILES.get('xml_file')
        xml_text = request.POST.get('xml_text', '')

        try:
            # Load XML from file or pasted text
            if input_method == 'upload' and xml_file:
                if not xml_file.name.endswith('.xml'):
                    messages.error(
                        request, "Invalid file type. Please upload an XML file.")
                    return redirect('xml_to_json_converter')
                file_data = xml_file.read().decode('utf-8', errors='replace').strip()
                root = ET.fromstring(file_data)
            elif input_method == 'paste' and xml_text.strip():
                root = ET.fromstring(xml_text.strip())
            else:
                messages.error(request, "Invalid input method or empty input.")
                return redirect('xml_to_json_converter')

            # If the root has children, treat each child as a separate record.
            if len(root) > 0:
                records = []
                for child in root:
                    record = ET_to_dict(child)
                    records.append(record)
                json_data = json.dumps(records, indent=4)
            else:
                # If root has no children, output a single record in a list.
                json_data = json.dumps([ET_to_dict(root)], indent=4)

        except Exception as e:
            messages.error(request, f"Error converting XML: {str(e)}")

    return render(request, 'Tools/DataConversion/xml_to_json_converter.html', {'json_data': json_data})


def yaml_to_json_converter(request):
    clear_messages(request)
    json_data = None

    if request.method == 'POST':
        input_method = request.POST.get('input_method')
        yaml_file = request.FILES.get('yaml_file')
        yaml_text = request.POST.get('yaml_text', '').strip()

        try:
            # Load YAML from file or pasted text
            if input_method == 'upload' and yaml_file:
                if not (yaml_file.name.endswith('.yaml') or yaml_file.name.endswith('.yml')):
                    messages.error(
                        request, "Invalid file type. Please upload a YAML file.")
                    return redirect('yaml_to_json_converter')
                file_data = yaml_file.read().decode('utf-8', errors='replace').strip()
                yaml_content = yaml.safe_load(file_data)
            elif input_method == 'paste':
                if not yaml_text:
                    messages.error(
                        request, "Empty YAML text provided. Please enter valid YAML content.")
                    return redirect('yaml_to_json_converter')
                try:
                    yaml_content = yaml.safe_load(yaml_text)
                except yaml.YAMLError as e:
                    messages.error(
                        request, f"Error parsing YAML text: {str(e)}")
                    return redirect('yaml_to_json_converter')

                # Additional validation: Ensure parsed content is not None
                if yaml_content is None:
                    messages.error(
                        request, "Parsed YAML content is empty. Please check your input.")
                    return redirect('yaml_to_json_converter')
            else:
                messages.error(request, "Invalid input method or empty input.")
                return redirect('yaml_to_json_converter')

            json_data = json.dumps(yaml_content, indent=4)

        except yaml.YAMLError as e:
            messages.error(request, f"Error converting YAML: {str(e)}")
        except Exception as e:
            messages.error(request, f"Unexpected error: {str(e)}")

    return render(request, 'Tools/DataConversion/yaml_to_json_converter.html', {'json_data': json_data})


def html_table_to_csv_converter(request):
    clear_messages(request)
    csv_data = None
    error_message = None

    if request.method == 'POST':
        html_content = request.POST.get('html_content', '').strip()
        html_file = request.FILES.get('html_file')

        if html_file:
            try:
                if not html_file.name.endswith('.html'):
                    raise ValueError(
                        "Invalid file type. Please upload an HTML file.")
                file_data = html_file.read().decode('utf-8', errors='replace').strip()
                soup = BeautifulSoup(file_data, 'html.parser')
            except Exception as e:
                error_message = f"Error reading HTML file: {str(e)}"
        elif html_content:
            try:
                soup = BeautifulSoup(html_content, 'html.parser')
            except Exception as e:
                error_message = f"Error parsing HTML content: {str(e)}"
        else:
            error_message = "Please provide HTML content or upload an HTML file."

        if not error_message:
            try:
                table = soup.find('table')

                if not table:
                    raise ValueError(
                        "No table found in the provided HTML content.")

                headers = [th.get_text(strip=True)
                           for th in table.find_all('th')]
                if not headers:
                    raise ValueError("No headers found in the table.")

                rows = []
                for tr in table.find_all('tr')[1:]:
                    cells = tr.find_all(['td', 'th'])
                    if len(cells) != len(headers):
                        raise ValueError(
                            "Row length does not match header length.")
                    row = {headers[i]: cells[i].get_text(
                        strip=True) for i in range(len(headers))}
                    rows.append(row)

                output = io.StringIO()
                writer = csv.DictWriter(output, fieldnames=headers)
                writer.writeheader()
                writer.writerows(rows)
                csv_data = output.getvalue()
            except Exception as e:
                error_message = f"Error converting HTML table: {str(e)}"

    return render(request, 'Tools/DataConversion/html_table_to_csv_converter.html', {
        'csv_data': csv_data,
        'error_message': error_message
    })


def qr_code_generator(request):
    clear_messages(request)
    generated_qr_url = None
    error_message = None
    if request.method == 'POST':
        qr_data = request.POST.get('qr_data')
        fill_color = request.POST.get('fill_color', 'black')
        back_color = request.POST.get('back_color', 'white')
        logo_file = request.FILES.get('logo_image')
        if qr_data:
            try:
                qr = qrcode.QRCode(
                    error_correction=qrcode.constants.ERROR_CORRECT_H,
                    box_size=10,
                    border=4,
                )
                qr.add_data(qr_data)
                qr.make(fit=True)
                img = qr.make_image(fill_color=fill_color,
                                    back_color=back_color).convert('RGB')
                if logo_file:
                    try:
                        logo = Image.open(logo_file)
                        img_w, img_h = img.size
                        factor = 4
                        size_w = int(img_w / factor)
                        size_h = int(img_h / factor)
                        logo = logo.resize((size_w, size_h), Image.LANCZOS)
                        pos = ((img_w - size_w) // 2, (img_h - size_h) // 2)
                        img.paste(logo, pos, mask=logo if logo.mode ==
                                  'RGBA' else None)
                    except Exception as e:
                        error_message = f"Error processing logo image: {str(e)}"
                buffer = io.BytesIO()
                img.save(buffer, format='PNG')
                buffer.seek(0)
                qr_b64 = base64.b64encode(buffer.read()).decode('utf-8')
                generated_qr_url = f"data:image/png;base64,{qr_b64}"
            except Exception as e:
                error_message = f"Error generating QR code: {str(e)}"
        else:
            error_message = "QR data is required."
    return render(request, 'Tools/QRandImaging/qr_code_generator.html', {
        'generated_qr_url': generated_qr_url,
        'error_message': error_message
    })


def barcode_generator(request):
    clear_messages(request)
    generated_barcode_url = None
    if request.method == 'POST':
        data_to_encode = request.POST.get('barcode_data', '').strip()
        if data_to_encode:
            # Generate barcode
            code128 = barcode.get_barcode_class('code128')
            my_code = code128(data_to_encode, writer=ImageWriter())

            # Save to memory
            buffer = io.BytesIO()
            my_code.write(buffer)
            buffer.seek(0)

            # Convert to base64
            barcode_b64 = base64.b64encode(buffer.read()).decode('utf-8')
            generated_barcode_url = f"data:image/png;base64,{barcode_b64}"

    return render(request, 'Tools/QRandImaging/barcode_generator.html', {
        'generated_barcode_url': generated_barcode_url
    })


def qr_code_scanner(request):
    clear_messages(request)
    scanned_data = None
    error_message = None
    if request.method == 'POST' and request.FILES.get('qr_image'):
        try:
            image_file = request.FILES['qr_image']
            img = Image.open(image_file)
            decoded_objects = decode(img)
            if decoded_objects:
                scanned_data = decoded_objects[0].data.decode('utf-8')
            else:
                error_message = "No QR code detected."
        except Exception as e:
            error_message = f"Error scanning QR code: {str(e)}"
    return render(request, 'Tools/QRandImaging/qr_code_scanner.html', {
        'scanned_data': scanned_data,
        'error_message': error_message
    })


def image_compression_tool(request):
    clear_messages(request)
    compressed_image_url = None
    if request.method == 'POST' and request.FILES.get('image_file'):
        image_file = request.FILES['image_file']
        # Save the original file size for comparison
        original_size = image_file.size
        img = Image.open(image_file)
        buffer = io.BytesIO()
        quality_str = request.POST.get('quality', '60')
        try:
            quality = int(quality_str)
        except ValueError:
            quality = 60
        if quality < 10:
            quality = 10
        elif quality > 100:
            quality = 100
        # Save compressed image
        img.save(buffer, format='JPEG', optimize=True, quality=quality)
        buffer.seek(0)
        comp_data = buffer.getvalue()
        # If compression results in a larger file than original, use the original file data
        if len(comp_data) > original_size:
            image_file.seek(0)
            comp_data = image_file.read()
        compressed_image_url = f"data:image/jpeg;base64,{base64.b64encode(comp_data).decode('utf-8')}"
    return render(request, 'Tools/QRandImaging/image_compression_tool.html', {
        'compressed_image_url': compressed_image_url
    })


def image_format_converter(request):
    clear_messages(request)
    converted_image_url = None
    if request.method == 'POST' and request.FILES.get('image_file'):
        image_file = request.FILES['image_file']
        desired_format = request.POST.get('desired_format', 'PNG')
        img = Image.open(image_file)
        buffer = io.BytesIO()
        img.save(buffer, format=desired_format)
        buffer.seek(0)

        image_b64 = base64.b64encode(buffer.read()).decode('utf-8')
        converted_image_url = f"data:image/{desired_format.lower()};base64,{image_b64}"

    return render(request, 'Tools/QRandImaging/image_format_converter.html', {
        'converted_image_url': converted_image_url
    })


def color_palette_extractor(request):
    clear_messages(request)
    color_palette = None
    if request.method == 'POST' and request.FILES.get('image_file'):
        image_file = request.FILES['image_file']
        color_thief = ColorThief(image_file)

        def rgb_to_hex(r, g, b):
            return f'#{r:02x}{g:02x}{b:02x}'

        palette = color_thief.get_palette(color_count=6)
        color_palette = [
            {
                'rgb': f'rgb({r},{g},{b})',
                'hex': rgb_to_hex(r, g, b)
            }
            for r, g, b in palette
        ]
    return render(request, 'Tools/QRandImaging/color_palette_extractor.html', {
        'color_palette': color_palette
    })


def photo_metadata_remover(request):
    clear_messages(request)
    cleaned_image_url = None
    error_message = None
    if request.method == 'POST' and request.FILES.get('image_file'):
        image_file = request.FILES['image_file']
        try:
            img = Image.open(image_file)
            # Re-save the image to strip off metadata
            buffer = io.BytesIO()
            fmt = img.format if img.format else 'JPEG'
            if fmt.upper() == 'JPEG':
                img.save(buffer, format='JPEG', quality=95)
            else:
                img.save(buffer, format=fmt)
            buffer.seek(0)
            image_b64 = base64.b64encode(buffer.read()).decode('utf-8')
            cleaned_image_url = f"data:image/{fmt.lower()};base64,{image_b64}"
        except Exception as e:
            error_message = f"Error processing image: {str(e)}"
    return render(request, 'Tools/QRandImaging/photo_metadata_remover.html', {
        'cleaned_image_url': cleaned_image_url,
        'error_message': error_message
    })


def exif_viewer(request):
    clear_messages(request)
    exif_data = None
    error_message = None

    if request.method == 'POST' and request.FILES.get('image_file'):
        image_file = request.FILES['image_file']
        try:
            # Open image using Pillow
            img = Image.open(image_file)
            exif = img.getexif()
            if exif:
                # Extract and format EXIF metadata
                exif_data = {TAGS.get(tag, tag): exif.get(tag)
                             for tag in exif.keys()}
                # Convert bytes values (e.g., MakerNote) to strings for better readability
                for key, value in exif_data.items():
                    if isinstance(value, bytes):
                        exif_data[key] = value.hex()  # Convert binary to hex
            else:
                error_message = "No EXIF metadata found in the image."
        except Exception as e:
            error_message = f"Error retrieving EXIF data: {str(e)}"

    return render(request, 'Tools/QRandImaging/exif_viewer.html', {
        'exif_data': exif_data,
        'error_message': error_message
    })
