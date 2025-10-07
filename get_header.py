import requests

def get_request(url, method="GET"):
    """
    Send an HTTP request to the given URL.
    Default method is GET, but can also use HEAD, OPTIONS, etc.
    Returns: response object or None if error
    """
    try:
        if method.upper() == "GET":
            response = requests.get(url, timeout=10)
        elif method.upper() == "HEAD":
            response = requests.head(url, timeout=10)
        elif method.upper() == "OPTIONS":
            response = requests.options(url, timeout=10)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")

        return response

    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Request failed for {url}: {e}")
        return None


def parse_headers(response):
    """
    Parse headers from a requests response object.
    Returns them as a dictionary.
    """
    if response is None:
        return {}

    return dict(response.headers)


def print_headers(headers_dict):
    """
    Print headers line by line (clean, no extra spaces).
    """
    print("\n📋 Response Headers:\n")
    for k, v in headers_dict.items():
        print(f"{k}: {v}")


def get_allowed_methods(url):
    """
    Check which HTTP methods are allowed by the server.
    Uses OPTIONS request.
    """
    response = get_request(url, method="OPTIONS")
    if response and "Allow" in response.headers:
        return [m.strip() for m in response.headers["Allow"].split(",")]
    return []
