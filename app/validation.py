"""Input validation and outbound-request safety checks."""
import ipaddress
import re
import socket
from urllib.parse import urlsplit


class ValidationError(ValueError):
    """The submitted domain is not acceptable. The message is safe to show."""


class UnsafeTargetError(Exception):
    """A request target is not allowed (private address, bad scheme, ...)."""


class ResolutionError(Exception):
    """A hostname could not be resolved to any address."""


_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_TLD_RE = re.compile(r"^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$")
# Suffixes used for internal / non-public names.
_BLOCKED_SUFFIXES = (".local", ".localhost", ".internal", ".lan",
                     ".intranet", ".corp", ".home.arpa", ".invalid")


def _looks_like_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def normalize_domain(raw):
    """Validate user input and return a lowercase ASCII domain.

    Accepts only a plain domain such as ``example.com``. URLs, paths, ports,
    credentials, IP addresses and internal-looking names are rejected.
    Internationalised names must be given in punycode (xn--...) form.
    """
    if not isinstance(raw, str):
        raise ValidationError("Please enter a domain name.")
    value = raw.strip().lower().rstrip(".")  # normalise case + trailing dot
    if not value:
        raise ValidationError("Please enter a domain name.")
    if len(value) > 253:
        raise ValidationError("That domain name is too long.")
    if any(ch in value for ch in ("/", "\\", "@", ":", "?", "#")):
        raise ValidationError(
            "Enter only a domain name such as example.com - "
            "not a URL, path, port or credentials."
        )
    if not re.fullmatch(r"[a-z0-9.-]+", value):
        raise ValidationError(
            "A domain may only contain letters a-z, digits, hyphens and dots."
        )
    if _looks_like_ip(value):
        raise ValidationError("IP addresses are not accepted - enter a domain name.")
    labels = value.split(".")
    if len(labels) < 2:
        raise ValidationError(
            "Enter a full domain such as example.com (single words are not accepted)."
        )
    if any(not _LABEL_RE.match(label) for label in labels):
        raise ValidationError("The domain contains an empty or malformed part.")
    if not _TLD_RE.match(labels[-1]):
        raise ValidationError("The top-level domain (e.g. .com) looks invalid.")
    if any(f".{value}".endswith(suffix) for suffix in _BLOCKED_SUFFIXES):
        raise ValidationError("Internal or non-public domain names are not accepted.")
    return value


def is_public_ip(address):
    """True only for globally routable unicast addresses.

    ``is_global`` is False for private, loopback, link-local, reserved,
    unspecified and carrier-grade-NAT ranges.
    """
    ip = ipaddress.ip_address(address.split("%")[0])
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped  # ::ffff:10.0.0.1 must be judged as 10.0.0.1
    return ip.is_global and not ip.is_multicast


def resolve_public_addresses(host):
    """Resolve ``host`` and make sure EVERY address is public.

    Strict on purpose: if even one address is internal, the request is blocked.
    """
    try:
        addresses = [str(ipaddress.ip_address(host))]  # host is an IP literal
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except (socket.gaierror, UnicodeError):
            raise ResolutionError("The host name could not be resolved.") from None
        addresses = sorted({info[4][0] for info in infos})
    if not addresses:
        raise ResolutionError("The host name did not resolve to any address.")
    for address in addresses:
        if not is_public_ip(address):
            raise UnsafeTargetError(
                "The host resolves to a non-public address, so the request was blocked."
            )
    return addresses


def check_url_is_safe(url):
    """Raise unless ``url`` is an http(s) URL to a public host on port 80/443.

    Called before the first request AND before every redirect hop, because a
    redirect could otherwise send us to an internal address.
    """
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        raise UnsafeTargetError("The URL is malformed.") from None
    if parts.scheme not in ("http", "https"):
        raise UnsafeTargetError("Only http and https URLs are allowed.")
    if parts.username or parts.password:
        raise UnsafeTargetError("URLs containing credentials are not allowed.")
    if not parts.hostname:
        raise UnsafeTargetError("The URL has no host name.")
    if port not in (None, 80, 443):
        raise UnsafeTargetError("Only the standard web ports 80 and 443 are allowed.")
    resolve_public_addresses(parts.hostname)