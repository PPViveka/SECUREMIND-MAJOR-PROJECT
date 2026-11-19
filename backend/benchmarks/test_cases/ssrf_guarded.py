"""
Benchmark Test Cases: Server-Side Request Forgery (SSRF) - Guarded Patterns (10 cases)
Ground Truth: GUARDED / BENIGN (False Positive Controls)
"""

import ipaddress
from urllib.parse import urlparse
import requests


ALLOWED_HOSTS = {"api.github.com", "hooks.slack.com", "api.stripe.com", "cdn.example.com"}


def is_safe_url(url_str):
    try:
        parsed = urlparse(url_str)
        if parsed.scheme not in {"https"}:
            return False
        host = parsed.hostname
        if not host:
            return False
        # Block localhost and private IP ranges
        try:
            ip = ipaddress.ip_address(host)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return False
        except ValueError:
            pass
        return host in ALLOWED_HOSTS
    except Exception:
        return False


def fetch_webhook_safe(webhook_url):
    """Guarded: Strict allowlist and scheme check before request (dev)"""
    if not is_safe_url(webhook_url):
        raise ValueError("Untrusted or private webhook target blocked")
    return requests.get(webhook_url, timeout=5).text


def download_remote_image_safe(image_url):
    """Guarded: Verified HTTPS scheme and allowed CDN domain (dev)"""
    parsed = urlparse(image_url)
    if parsed.scheme != "https" or parsed.hostname != "cdn.example.com":
        raise ValueError("Invalid image host")
    return requests.get(image_url, timeout=5).content


def forward_api_call_safe(target_endpoint, payload):
    """Guarded: Host allowlist prevents intranet probing (dev)"""
    if not is_safe_url(target_endpoint):
        raise PermissionError("Access to internal or unapproved endpoint denied")
    return requests.post(target_endpoint, json=payload, timeout=5).json()


def fetch_rss_feed_safe(feed_url):
    """Guarded: Blocks cloud metadata IP and enforces safe domain (dev)"""
    if not is_safe_url(feed_url):
        raise ValueError("Blocked feed URL")
    return requests.get(feed_url, timeout=5).text


def proxy_service_request_safe(url_param):
    """Guarded: Validates scheme and allowed destination (dev)"""
    if not is_safe_url(url_param):
        raise ValueError("Invalid proxy destination")
    return requests.get(url_param, timeout=5).text


def ping_webhook_status_safe(callback_url):
    """Guarded: Host containment check before HEAD request (eval)"""
    if not is_safe_url(callback_url):
        raise ValueError("Disallowed callback")
    return requests.head(callback_url, timeout=3).status_code


def import_remote_calendar_safe(ical_url):
    """Guarded: Checks domain allowlist for calendar export (eval)"""
    if not is_safe_url(ical_url):
        raise ValueError("Calendar domain not allowed")
    return requests.get(ical_url, timeout=5).text


def preview_link_metadata_safe(user_url):
    """Guarded: Blocks private network links (eval)"""
    if not is_safe_url(user_url):
        raise ValueError("Link preview target blocked")
    return requests.get(user_url, timeout=3).headers.get("Content-Type")


def load_remote_theme_safe(theme_url):
    """Guarded: Enforces HTTPS and approved CDN (eval)"""
    parsed = urlparse(theme_url)
    if parsed.scheme != "https" or parsed.hostname != "cdn.example.com":
        raise ValueError("Theme host not allowed")
    return requests.get(theme_url, timeout=5).text


def sync_partner_inventory_safe(endpoint_url):
    """Guarded: Validated partner endpoint check (eval)"""
    if not is_safe_url(endpoint_url):
        raise ValueError("Invalid partner API endpoint")
    return requests.get(endpoint_url, timeout=5).json()
