from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

_SAFE_FILE_RE = re.compile(r'[^A-Za-z0-9_.-]+')
_ALLOWED_WEB_SCHEMES = {'http', 'https'}


def safe_cache_name(value: str) -> str:
    safe = _SAFE_FILE_RE.sub('_', (value or '').strip())
    return safe[:120] or 'site'


def normalize_http_url(value: str) -> str:
    raw = (value or '').strip()
    if not raw:
        raise ValueError('Website field is empty.')

    preliminary = urlparse(raw)
    if preliminary.scheme and preliminary.scheme.lower() not in _ALLOWED_WEB_SCHEMES:
        raise ValueError('Only http:// and https:// websites can be opened.')

    if '://' not in raw:
        raw = f'https://{raw}'
    parsed = urlparse(raw)
    if parsed.scheme.lower() not in _ALLOWED_WEB_SCHEMES or not parsed.netloc:
        raise ValueError('Only http:// and https:// websites can be opened.')
    return parsed.geturl()


def _is_private_or_internal_host(host: str) -> bool:
    """Return True when a host must never be sent to an external favicon service."""
    host = (host or '').strip().lower().rstrip('.')
    if not host:
        return True

    try:
        ip = ipaddress.ip_address(host.strip('[]'))
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        )
    except ValueError:
        pass

    blocked_suffixes = ('.local', '.localhost', '.internal', '.intranet', '.lan', '.home', '.corp', '.test')
    if host == 'localhost' or host.endswith(blocked_suffixes):
        return True

    # Single-label names such as "router", "nas", or "intranet" often identify
    # local systems and should not be disclosed to a third-party favicon service.
    if '.' not in host:
        return True

    return False


def safe_favicon_host(value: str) -> str:
    raw = (value or '').strip()
    if not raw:
        return ''
    if '://' not in raw:
        raw = f'https://{raw}'
    parsed = urlparse(raw)
    if parsed.scheme.lower() not in _ALLOWED_WEB_SCHEMES:
        return ''
    host = parsed.netloc.lower().split('@')[-1].split(':')[0].rstrip('.')
    if not host or any(ch.isspace() for ch in host):
        return ''
    host = host.removeprefix('www.')
    if _is_private_or_internal_host(host):
        return ''
    return host
