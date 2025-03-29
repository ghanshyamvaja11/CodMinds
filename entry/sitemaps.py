from django.contrib.sitemaps import Sitemap
from django.urls import reverse


class StaticViewSitemap(Sitemap):
    priority = 0.5
    changefreq = 'daily'

    def items(self):
        return [
            'home', 'about', 'servicies', 'contact', 'T&C', 'privacy_policy',
            'cancellation_refund_policies', 'internship_program', 'web_development', 'user_login', 'user_signup',
            'software_development', 'data_analytics', 'error_404_view', 'hire_us',
            'carrier', 'tools_library', 'subscribe', 'code_formatter', 'json_formatter_validator',
            'base64_encoder_decoder', 'case_converter', 'string_hash_generator', 'url_encoder_decoder',
            'jwt_decoder_generator', 'regex_tester', 'api_tester', 'network_analyzer',
            'rest_api_tester', 'http_headers_inspector', 'dns_lookup_tool', 'whois_lookup',
            'ip_address_lookup', 'port_scanner',
            'meta_tag_analyzer', 'ssl_certificate_checker',
            'password_generator', 'uuid_generator', 'xss_vulnerability_tester', 'sql_injection_tester', 'jwt_expiry_checker', 'csv_to_json_converter', 'json_to_csv_converter', 'html_table_to_json_converter', 'html_table_to_csv_converter', 'xml_to_json_converter', 'yaml_to_json_converter',
            'qr_code_generator', 'barcode_generator',
            'image_compression_tool', 'image_format_converter', 'color_palette_extractor',
            'photo_metadata_remover', 'exif_viewer'
        ]

    def location(self, item):
        return reverse(item)
