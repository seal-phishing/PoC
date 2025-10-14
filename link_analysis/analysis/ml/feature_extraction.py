import ipaddress
from urllib.parse import urlparse

# Optional dependency for extracting subdomain/domain/suffix
try:
    import tldextract
except ImportError:
    tldextract = None

# List of known URL shortening services
SHORTENING_SERVICES = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "is.gd", "buff.ly"
}

def extract_features(url: str) -> dict:
    """
    Extract a set of features from the given URL for use in phishing detection.

    Args:
        url (str): The URL to analyze.

    Returns:
        dict: A dictionary of extracted feature values.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""

    # Extract domain, subdomain, and TLD using tldextract if available
    if tldextract:
        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
        subdomain = ext.subdomain or ""
        tld = ext.suffix
    else:
        parts = hostname.split(".")
        domain = hostname
        subdomain = ""
        tld = parts[-1] if len(parts) > 1 else ""

    features = {
        "length_url": len(url),
        "length_hostname": len(hostname),
        "ip": 1 if is_ip(hostname) else 0,
        "nb_dots": url.count("."),
        "nb_hyphens": url.count("-"),
        "nb_at": url.count("@"),
        "nb_qm": url.count("?"),
        "nb_eq": url.count("="),
        "nb_slash": url.count("/"),
        "nb_colon": url.count(":"),
        "https_token": 1 if "https" in path.lower() else 0,
        "ratio_digits_url": count_digits(url) / len(url),
        "ratio_digits_host": count_digits(hostname) / len(hostname) if hostname else 0,
        "tld": tld,
        "prefix_suffix": 1 if "-" in domain else 0,
        "nb_subdomains": subdomain.count("."),
        "has_punycode": 1 if hostname.startswith("xn--") else 0,
        "is_shortened": 1 if hostname in SHORTENING_SERVICES else 0,
        "path_ext": path.split(".")[-1] if "." in path else "",
        "scheme": parsed.scheme,
    }

    return features

def is_ip(s: str) -> bool:
    """
    Check if a string is a valid IP address.

    Args:
        s (str): String to check.

    Returns:
        bool: True if the string is an IP address, False otherwise.
    """
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False

def count_digits(s: str) -> int:
    """
    Count the number of digits in a string.

    Args:
        s (str): Input string.

    Returns:
        int: Number of numeric characters.
    """
    return sum(1 for c in s if c.isdigit())
