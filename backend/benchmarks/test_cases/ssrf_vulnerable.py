"""
Benchmark Test Cases: Server-Side Request Forgery (SSRF) - Vulnerable Patterns (10 cases)
Ground Truth: VULNERABLE
"""

import urllib.request
import requests


def fetch_webhook(webhook_url):
    """Vulnerable: Direct request to arbitrary user-supplied URL (dev)"""
    return requests.get(webhook_url).text


def download_remote_image(image_url):
    """Vulnerable: urllib.request.urlopen without scheme or host validation (dev)"""
    with urllib.request.urlopen(image_url) as resp:
        return resp.read()


def forward_api_call(target_endpoint, payload):
    """Vulnerable: requests.post to arbitrary URL allows internal port probing (dev)"""
    return requests.post(target_endpoint, json=payload).json()


def fetch_rss_feed(feed_url):
    """Vulnerable: Unconstrained GET allows hitting AWS metadata 169.254.169.254 (dev)"""
    res = requests.get(feed_url, timeout=5)
    return res.text


def proxy_service_request(url_param):
    """Vulnerable: urllib.request.Request on user input (dev)"""
    req = urllib.request.Request(url_param)
    return urllib.request.urlopen(req).read()


def ping_webhook_status(callback_url):
    """Vulnerable: requests.head on arbitrary callback URL (eval)"""
    return requests.head(callback_url).status_code


def import_remote_calendar(ical_url):
    """Vulnerable: GET on user calendar URL without host check (eval)"""
    return requests.get(ical_url).text


def preview_link_metadata(user_url):
    """Vulnerable: Direct HTTP request to user-submitted link (eval)"""
    resp = requests.get(user_url, timeout=3)
    return resp.headers.get("Content-Type")


def load_remote_theme(theme_url):
    """Vulnerable: urllib.request urlopen for remote CSS (eval)"""
    return urllib.request.urlopen(theme_url).read()


def sync_partner_inventory(endpoint_url):
    """Vulnerable: Unsanitized partner inventory sync URL (eval)"""
    return requests.get(endpoint_url).json()
