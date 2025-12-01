# ssl_check.py
# Minimal SSL/TLS scanner for FYP
# - Verified handshake (verify ON)
# - Non-verified handshake (verify OFF) to detect TLS presence
# - Protocol version probing (openssl if available)
# - Cipher suite observation (openssl if available)
# - HTTP -> HTTPS redirect check and HSTS header read (verify=False allowed)
#
# Outputs human-friendly findings list suitable for integration with main.py

import ssl
import socket
import datetime
import subprocess
import re
import tempfile
import os
import urllib.parse
import requests
from typing import List, Dict, Any, Tuple, Optional
from colorama import Fore, Style

OPENSSSL_TIMEOUT = 8  # seconds for openssl subprocess


# ----------------------
# Helpers
# ----------------------
def _run_openssl(host: str, port: int = 443, proto_flag: Optional[str] = None, timeout: int = OPENSSSL_TIMEOUT) -> Optional[str]:
    """Run openssl s_client quietly and return combined stdout+stderr, or None on failure."""
    cmd = ["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host, "-brief"]  # -brief helps reduce noise on newer openssl
    # Some openssl builds reject unknown flags; the -brief is optional, but keep it — if it errors we still capture output.
    if proto_flag:
        # proto_flag should be like '-tls1_2' or '-tls1_3' or '-tls1', '-ssl3', etc.
        cmd.insert(1, proto_flag)
    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = proc.communicate(input="Q\n", timeout=timeout)
        combined = (stdout or "") + (stderr or "")
        return combined
    except Exception:
        return None


def _openssl_available() -> bool:
    try:
        proc = subprocess.Popen(["openssl", "version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        out, _ = proc.communicate(timeout=3)
        return proc.returncode == 0 and bool(out.strip())
    except Exception:
        return False


def _parse_cipher_from_openssl(out: str) -> Optional[str]:
    """Try a few patterns to extract negotiated cipher from openssl output."""
    if not out:
        return None
    patterns = [
        r'Cipher\s*:\s*([^\s,]+)',                # "Cipher : ECDHE-RSA-AES256-GCM-SHA384"
        r'Cipher\s*:\s*([A-Za-z0-9\-_]+)',        # fallback
        r'New, TLSv[0-9.]+, Cipher is ([^\s,]+)', # some outputs
        r'Cipher is ([^\s,]+)',
    ]
    for p in patterns:
        m = re.search(p, out)
        if m:
            return m.group(1).strip()
    return None


def _parse_server_temp_key_bits(out: str) -> Optional[int]:
    """Return DH temp key size in bits if present in openssl output (e.g., 'Server Temp Key: DH, 1024 bits')."""
    if not out:
        return None
    m = re.search(r'Server Temp Key:\s*[^,]+,\s*([\d]+)\s*bits', out, re.IGNORECASE)
    if m:
        try:
            return int(m.group(1))
        except Exception:
            return None
    # alternative pattern
    m2 = re.search(r'([0-9]{3,4})\s*bits', out)
    if m2:
        try:
            return int(m2.group(1))
        except Exception:
            return None
    return None


def _is_cipher_weak(cipher_name: Optional[str]) -> Tuple[bool, List[str]]:
    """Return (is_weak, list_of_weak_reasons) for a cipher name."""
    if not cipher_name:
        return False, []
    c = cipher_name.upper()
    weak_reasons = []
    # detect some classic weak token names
    if any(x in c for x in ["RC4", "3DES", "DES", "EXPORT", "NULL", "ADH", "aNULL", "MD5"]):
        weak_reasons.append("Weak cipher or weak MAC (RC4/3DES/DES/EXPORT/NULL/MD5)")
    # AEAD vs not
    if not any(x in c for x in ["GCM", "POLY1305", "CHACHA20"]):
        # Non-AEAD cipher (not always weak by itself, but less preferred)
        weak_reasons.append("Non-AEAD cipher (prefer AES-GCM / ChaCha20-Poly1305)")
    return (len(weak_reasons) > 0), weak_reasons


def _human_date(dt: Optional[datetime.datetime]) -> str:
    if dt is None:
        return "N/A"
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


# ----------------------
# Certificate helpers
# ----------------------
def _get_cert_via_ssl_ctx(host: str, port: int = 443, verify: bool = True, timeout: int = 5) -> Tuple[Optional[dict], Optional[str]]:
    """
    Perform a TLS handshake using python ssl.
    If verify=True, perform normal validation (may raise ssl.CertificateError or other exceptions).
    Returns (cert_dict (as from SSLSocket.getpeercert()), error_string)
    If error_string is non-None -> handshake/validation failed.
    """
    try:
        if verify:
            ctx = ssl.create_default_context()
        else:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
                # also get TLS version
                tls_ver = getattr(ss, "version", lambda: None)()
                return {"cert": cert, "tls_version": tls_ver}, None
    except Exception as e:
        return None, str(e)


def _parse_cert_dates(cert: dict) -> Tuple[Optional[datetime.datetime], Optional[datetime.datetime]]:
    """
    Parse notBefore and notAfter values from getpeercert() dict into datetimes (UTC).
    Returns (notBefore_dt, notAfter_dt) or (None, None) when unparsable.
    """
    if not cert:
        return None, None
    nb = cert.get("notBefore")
    na = cert.get("notAfter")
    def _parse_field(v):
        if not v:
            return None
        # Usually like 'Jun  1 00:00:00 2025 GMT'
        for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT"):
            try:
                return datetime.datetime.strptime(v, fmt)
            except Exception:
                continue
        # fallback: try email.utils parsedate_to_datetime
        try:
            from email.utils import parsedate_to_datetime
            return parsedate_to_datetime(v)
        except Exception:
            return None
    return _parse_field(nb), _parse_field(na)


# ----------------------
# High-level checks
# ----------------------
def _probe_protocols_with_openssl(host: str, port: int = 443) -> Tuple[List[str], List[str], Optional[str]]:
    """
    Use openssl s_client with version flags to detect supported and deprecated protocols.
    Returns (supported_list, deprecated_list, error_or_note_if_any)
    If openssl not available, return ([], [], "openssl-not-found")
    """
    if not _openssl_available():
        return [], [], "openssl-not-found"

    protos = {
        "SSLv2": "-ssl2",
        "SSLv3": "-ssl3",
        "TLS 1.0": "-tls1",
        "TLS 1.1": "-tls1_1",
        "TLS 1.2": "-tls1_2",
        "TLS 1.3": "-tls1_3"
    }
    supported = []
    deprecated = []
    note = None

    for name, flag in protos.items():
        out = _run_openssl(host, port=port, proto_flag=flag)
        if not out:
            continue
        # declare success if we see signs of a completed handshake
        success = any(x in out for x in ["Cipher is", "Cipher :", "Verify return code: 0", "depth="])
        failure = any(x in out.lower() for x in ["wrong version", "no protocols available", "handshake failure", "no shared cipher"])
        if success and not failure:
            if name in ("SSLv2", "SSLv3", "TLS 1.0", "TLS 1.1"):
                deprecated.append(name)
            else:
                supported.append(name)
    return supported, deprecated, note


def _probe_cipher_and_tempkey(host: str, port: int = 443) -> Dict[str, Any]:
    """
    Attempt to observe negotiated cipher and server temp key (DH) via openssl.
    Returns a dict with keys:
      negotiated_cipher, weak_ciphers (list), forward_secrecy (bool), dh_key_bits (int or None), openssl_output
    If openssl not available, returns dict with openssl_available=False
    """
    res = {
        "negotiated_cipher": None,
        "weak_ciphers": [],
        "forward_secrecy": False,
        "dh_key_bits": None,
        "openssl_available": True,
        "openssl_output": None
    }
    if not _openssl_available():
        res["openssl_available"] = False
        return res

    out = _run_openssl(host, port)
    res["openssl_output"] = out
    cipher = _parse_cipher_from_openssl(out) if out else None
    res["negotiated_cipher"] = cipher
    # weakness analysis
    is_weak, reasons = _is_cipher_weak(cipher)
    if is_weak:
        res["weak_ciphers"].extend(reasons or [cipher or "Unknown"])
    # forward secrecy: simple heuristic
    if cipher and any(x in cipher.upper() for x in ["ECDHE", "DHE"]):
        res["forward_secrecy"] = True
    # DH temp key bits
    dhbits = _parse_server_temp_key_bits(out or "")
    res["dh_key_bits"] = dhbits
    if dhbits and dhbits < 2048:
        res["weak_ciphers"].append(f"Weak DH ({dhbits} bits)")
    return res


def check_http_redirect_and_hsts(target_url: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """
    Check http://host redirect -> https and detect HSTS header.
    Returns (http_to_https_redirect_bool, hsts_dict_or_None)
    hsts_dict example: {'present': True, 'max_age': 31536000, 'includeSubDomains': True, 'preload': False, 'read_with_verify': False}
    """
    p = urllib.parse.urlparse(target_url)
    hostname = p.hostname
    if not hostname:
        return False, None

    # Build a plain HTTP URL
    http_url = f"http://{hostname}"
    if p.port:
        http_url = f"http://{hostname}:{p.port}"

    redirect_ok = False
    try:
        # plain HTTP request, allow redirects disabled so we can inspect Location header
        r = requests.get(http_url, timeout=5, allow_redirects=False)
        if r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("Location", "")
            if loc.startswith("https://"):
                redirect_ok = True
    except Exception:
        # unreachable over plain HTTP or other error -> treat as no redirect observed
        redirect_ok = False

    # Check HSTS: try to fetch via HTTPS and read Strict-Transport-Security
    hsts = None
    try:
        https_url = f"https://{hostname}"
        if p.port:
            https_url = f"https://{hostname}:{p.port}"
        # use verify=False so we can always read headers (but record that we used verify=False)
        r2 = requests.get(https_url, timeout=5, verify=False)
        h = r2.headers.get("Strict-Transport-Security")
        if h:
            m = re.search(r"max-age\s*=\s*(\d+)", h, re.IGNORECASE)
            hsts = {
                "present": True,
                "max_age": int(m.group(1)) if m else 0,
                "includeSubDomains": "includesubdomains" in h.lower(),
                "preload": "preload" in h.lower(),
                "header_raw": h,
                "read_with_verify": False
            }
        else:
            hsts = {"present": False, "read_with_verify": False}
    except Exception:
        hsts = None

    return redirect_ok, hsts


# ----------------------
# Public API
# ----------------------
def run_ssl_check(target_url, verbose=False):
    """
    Improved run_ssl_check — updated formatting for no-TLS case and risk rating output.

    Returns: list of findings (each a dict).
    """
    findings = []

    p = urllib.parse.urlparse(target_url)
    host = p.hostname
    port = p.port or 443

    if not host:
        print(Fore.RED + "[ERROR] Invalid URL." + Style.RESET_ALL)
        return []

    # Header (show host:port)
    print(Fore.CYAN + "\n🔒 SSL/TLS Security Analysis" + Style.RESET_ALL)
    print(Fore.CYAN + "════════════════════════════════════════════════════════════════" + Style.RESET_ALL)
    print(Fore.WHITE + f"Target Host: {host}:{port}" + Style.RESET_ALL)
    print(Fore.WHITE + "-" * 64 + Style.RESET_ALL)

    # Keep evidence strings
    verification_error = None
    nonverified_error = None
    https_supported = False
    certificate_info = None

    # ---------------------------
    # 1) Verified handshake (certificate validation)
    # ---------------------------
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                https_supported = True
                certificate_info = get_certificate_details(host, port)
    except Exception as e:
        verification_error = str(e)

    # ---------------------------
    # 2) If verified fails, attempt non-verified handshake to detect TLS presence
    # ---------------------------
    if not https_supported:
        try:
            ctx2 = ssl.SSLContext()  # negotiate
            ctx2.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=5) as s2:
                with ctx2.wrap_socket(s2, server_hostname=host) as ss2:
                    https_supported = True
                    # best-effort: try to read binary cert (may or may not be available)
                    try:
                        der = None
                        try:
                            der = ss2.getpeercert(binary_form=True)
                        except Exception:
                            der = None
                        if der:
                            parsed_text = extract_cert_openssl(der)
                            # keep certificate_info only if get_certificate_details didn't already succeed
                            certificate_info = certificate_info or {}
                    except Exception:
                        pass
        except Exception as e:
            nonverified_error = str(e)
            https_supported = False

    # ---------------------------
    # 3) If neither verified nor non-verified succeed: no TLS — print notice + risk rating + finding
    # ---------------------------
    if not https_supported:
        evidence = verification_error or nonverified_error or "TLS handshake failed"

        # Notice block with the extra explanatory line the user requested
        print(Fore.YELLOW + f"\n[Notice] No TLS/HTTPS service detected on {host}:{port}." + Style.RESET_ALL)
        print(Fore.YELLOW + "This usually means the server is serving plain HTTP (or another protocol) at this address/port," + Style.RESET_ALL)
        print(Fore.YELLOW + "so certificate, protocol and cipher details cannot be collected." + Style.RESET_ALL)
        print(Fore.YELLOW + f"Detected error: {evidence}" + Style.RESET_ALL)
        print(Fore.WHITE + "-" * 64 + Style.RESET_ALL)

        # Build finding (order: Current Value, Evidence, Recommendation)
        finding = {
            "Category": "SSL/TLS",
            "Severity": "High",
            "Description": "HTTPS Not Supported",
            "Current Value": f"No TLS listener detected on {host}:{port}.",
            "Evidence": evidence,
            "Recommendation": "Enable HTTPS and configure a valid certificate. Ensure a TLS listener is present on port 443 (or the configured port)."
        }
        findings.append(finding)

        # Print risk rating block (High + CVSS 9.8 as requested)
        print(Fore.RED + "RISK RATING: Issues Detected" + Style.RESET_ALL)
        print(Fore.WHITE + f"Severity: High" + Style.RESET_ALL)
        print(Fore.WHITE + f"CVSS: 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)" + Style.RESET_ALL)
        print(Fore.YELLOW + "\nFindings:" + Style.RESET_ALL)

        # Format the single finding exactly as requested
        print(Fore.WHITE + "1. HTTPS Not Supported" + Style.RESET_ALL)
        print(Fore.WHITE + f"   Current Value: {finding['Current Value']}" + Style.RESET_ALL)
        print(Fore.WHITE + f"   Evidence: {finding['Evidence']}" + Style.RESET_ALL)
        print(Fore.WHITE + f"   Recommendation: {finding['Recommendation']}" + Style.RESET_ALL)

        print(Fore.CYAN + "════════════════════════════════════════════════════════════════" + Style.RESET_ALL)
        return findings

    # ---------------------------
    # 4) TLS is present (verified or non-verified). Continue with the rest of checks.
    #    (The remainder of the run_ssl_check implementation can remain as before.)
    # ---------------------------
    # For brevity, call the previously implemented logic to collect protocol/cipher/cert/HSTS info.
    # We'll reuse the same steps from your existing implementation: protocol probing, cipher suites,
    # certificate details, HTTP->HTTPS redirect and HSTS checks — and collect findings accordingly.
    #
    # (Here we re-use the logic from the full implementation you already have.)
    try:
        # Protocols
        supported, deprecated = check_protocol_support(host, port)
    except Exception:
        supported, deprecated = [], []

    try:
        cipher, fse, weak, weak_dh, temp = get_cipher_suites(host, port)
    except Exception:
        cipher, fse, weak, weak_dh, temp = None, False, [], False, None

    cert = certificate_info

    # Certificate-related findings if verification_error exists
    if verification_error:
        findings.append({
            "Category": "SSL/TLS",
            "Severity": "High",
            "Description": "SSL Certificate Validity – Expired / Not Yet Valid / Mismatch",
            "Current Value": f"Status: validation error ({verification_error})",
            "Evidence": verification_error,
            "Recommendation": "Install a valid SSL certificate from a trusted CA and ensure the certificate matches the host name."
        })

    # Deprecated protocols -> Medium
    if deprecated:
        findings.append({
            "Category": "SSL/TLS",
            "Severity": "Medium",
            "Description": "Use of Weak Protocol Version",
            "Current Value": f"{', '.join(deprecated)}",
            "Evidence": f"Deprecated protocols detected: {', '.join(deprecated)}",
            "Recommendation": "Disable deprecated versions. Only allow TLS 1.2 and TLS 1.3."
        })

    # Weak ciphers / missing FSE -> Medium
    if weak:
        findings.append({
            "Category": "SSL/TLS",
            "Severity": "Medium",
            "Description": "Use of Weak Cipher Suites",
            "Current Value": ", ".join(weak),
            "Evidence": f"Weak ciphers: {', '.join(weak)}",
            "Recommendation": "Remove weak cipher suites and enable modern AEAD suites (AES-GCM, ChaCha20-Poly1305) with ECDHE."
        })

    if (cipher and not fse) or weak_dh:
        # Missing forward secrecy or weak DH
        if cipher and not fse:
            findings.append({
                "Category": "SSL/TLS",
                "Severity": "Medium",
                "Description": "Missing Forward Secrecy",
                "Current Value": f"Negotiated Cipher: {cipher}\nForward Secrecy: No",
                "Evidence": f"Negotiated: {cipher}",
                "Recommendation": "Enable ECDHE/DHE cipher suites to provide forward secrecy (ECDHE preferred)."
            })
        if weak_dh:
            findings.append({
                "Category": "SSL/TLS",
                "Severity": "Medium",
                "Description": "Weak Diffie-Hellman Key Size",
                "Current Value": "DH Key Size appears <= 1024 bits",
                "Evidence": "Temporary DH key length reported <= 1024 bits",
                "Recommendation": "Enforce DH >= 2048 bits or use ECDHE (X25519/P-256)."
            })

    # Certificate details (expiry / duration / signature)
    if cert:
        issuer = cert.get("issuer", "Unknown")
        sig_alg = cert.get("signature_algorithm", "Unknown")
        key_type = cert.get("key_type", "Unknown")
        key_size = cert.get("key_size", "Unknown")
        valid_from = cert.get("valid_from", "N/A")
        expiry_date = cert.get("expiry_date", "N/A")
        days_left = cert.get("days_until_expiry")
        total_days = cert.get("total_validity_days")

        # Expiry soon -> Medium
        if days_left is not None and 0 <= days_left < 30:
            findings.append({
                "Category": "SSL/TLS",
                "Severity": "Medium",
                "Description": "SSL Certificate Validity – Expiry",
                "Current Value": f"Expiry Date: {expiry_date}\nDays Until Expiry: {days_left}",
                "Evidence": f"Days until expiry: {days_left}",
                "Recommendation": "Renew certificate before expiry to avoid service interruption."
            })

        # Validity too long -> Medium
        if total_days and total_days > 397:
            findings.append({
                "Category": "SSL/TLS",
                "Severity": "Medium",
                "Description": "SSL Certificate Validity – Duration Too Long",
                "Current Value": f"Certificate Validity: {total_days} days",
                "Evidence": f"Total validity days: {total_days}",
                "Recommendation": "Replace certificate with one valid for ≤ 397 days."
            })

        # Weak signature algorithm
        if sig_alg and re.search(r"sha1|md5", str(sig_alg), re.IGNORECASE):
            findings.append({
                "Category": "SSL/TLS",
                "Severity": "Medium",
                "Description": "Weak Signature Algorithm",
                "Current Value": str(sig_alg),
                "Evidence": f"Signature algorithm: {sig_alg}",
                "Recommendation": "Use certificates signed with SHA-256 or stronger."
            })

    # HTTPS Support: redirect & HSTS
    try:
        redirect = check_http_redirect(target_url)
    except Exception:
        redirect = False

    try:
        hsts = check_hsts(target_url)
    except Exception:
        hsts = None

    if not redirect:
        findings.append({
            "Category": "SSL/TLS",
            "Severity": "Medium",
            "Description": "HTTPS Not Enforced (No HTTP → HTTPS Redirect)",
            "Current Value": "Plain HTTP requests are not redirected to HTTPS (or redirect not observed).",
            "Evidence": "no-redirect",
            "Recommendation": "Configure the server to redirect all HTTP traffic to HTTPS (301/307) and use HSTS."
        })

    if isinstance(hsts, dict) and not hsts.get("present"):
        findings.append({
            "Category": "SSL/TLS",
            "Severity": "Medium",
            "Description": "Missing HSTS (HTTP Strict Transport Security)",
            "Current Value": "HSTS header not present",
            "Evidence": "no-hsts",
            "Recommendation": "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
        })

    # ---------------------------
    # Final: print summaries (certificate/proto/cipher/hsts) then risk rating block (if findings)
    # ---------------------------
    # Certificate block (friendly)
    if cert:
        print(Fore.WHITE + "\nSSL Certificate Information:" + Style.RESET_ALL)
        print(Fore.WHITE + f"  Issuer: {cert.get('issuer','Unknown')}" + Style.RESET_ALL)
        print(Fore.WHITE + f"  Signature Algorithm: {cert.get('signature_algorithm','Unknown')}" + Style.RESET_ALL)
        keyinfo = cert.get('key_type','Unknown') + (f" {cert.get('key_size')}-bit" if cert.get('key_size') and cert.get('key_size') != 'Unknown' else "")
        print(Fore.WHITE + f"  Key Type / Size: {keyinfo}" + Style.RESET_ALL)
        print(Fore.WHITE + f"  Valid From: {cert.get('valid_from','N/A')}" + Style.RESET_ALL)
        print(Fore.WHITE + f"  Expiry Date: {cert.get('expiry_date','N/A')}" + Style.RESET_ALL)
        print(Fore.WHITE + f"  Days Until Expiry: {cert.get('days_until_expiry')}" + Style.RESET_ALL)
    else:
        if verification_error:
            print(Fore.YELLOW + "\nSSL Certificate Information: Unable to obtain certificate details due to validation error." + Style.RESET_ALL)
            print(Fore.YELLOW + f"  Validation error: {verification_error}" + Style.RESET_ALL)

    # Protocol and cipher summary
    print(Fore.WHITE + "\nProtocol Versions:" + Style.RESET_ALL)
    print(Fore.WHITE + f"  Supported: {', '.join(supported) if supported else 'Unknown'}" + Style.RESET_ALL)
    if deprecated:
        print(Fore.RED + f"  Deprecated Versions Detected: {', '.join(deprecated)}" + Style.RESET_ALL)

    print(Fore.WHITE + "\nCipher Suites:" + Style.RESET_ALL)
    print(Fore.WHITE + f"  Negotiated Cipher: {cipher if cipher else 'N/A'}" + Style.RESET_ALL)
    if weak:
        print(Fore.RED + f"  Weak Ciphers Detected: {', '.join(weak)}" + Style.RESET_ALL)
    print(Fore.WHITE + f"  Forward Secrecy: {'Yes' if fse else 'No'}" + Style.RESET_ALL)

    print(Fore.WHITE + "\nHTTPS Support:" + Style.RESET_ALL)
    print(Fore.WHITE + f"  HTTPS Supported: {'Yes' if https_supported else 'No'}" + Style.RESET_ALL)
    print(Fore.WHITE + f"  HTTP → HTTPS Redirect: {'Yes' if redirect else 'No'}" + Style.RESET_ALL)
    if isinstance(hsts, dict):
        print(Fore.WHITE + ("  HSTS: Present" if hsts.get("present") else "  HSTS: Not Present") + Style.RESET_ALL)
    else:
        print(Fore.WHITE + "  HSTS: Unknown" + Style.RESET_ALL)

    print(Fore.CYAN + "-" * 64 + Style.RESET_ALL)

    # Final risk rating block (only print if there are findings)
    if findings:
        severities = [f.get("Severity", "Low") for f in findings]
        if "High" in severities:
            overall = "High"
            overall_cvss = "9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)"
        elif any(s == "Medium" for s in severities):
            overall = "Medium"
            overall_cvss = "5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)"
        else:
            overall = None
            overall_cvss = None

        if overall:
            print(Fore.RED + "RISK RATING: Issues Detected" + Style.RESET_ALL)
            print(Fore.WHITE + f"Severity: {overall}" + Style.RESET_ALL)
            if overall_cvss:
                print(Fore.WHITE + f"CVSS: {overall_cvss}" + Style.RESET_ALL)
            print(Fore.YELLOW + "\nFindings:" + Style.RESET_ALL)

            for i, f in enumerate(findings, start=1):
                # Print description line as numbered item
                print(Fore.WHITE + f"{i}. {f.get('Description')}" + Style.RESET_ALL)
                # Print fields in requested order
                if f.get("Current Value"):
                    print(Fore.WHITE + f"   Current Value: {f.get('Current Value')}" + Style.RESET_ALL)
                if f.get("Evidence"):
                    ev = str(f.get("Evidence"))
                    if len(ev) > 400:
                        ev = ev[:400] + " ... (truncated)"
                    print(Fore.WHITE + f"   Evidence: {ev}" + Style.RESET_ALL)
                if f.get("Recommendation"):
                    print(Fore.WHITE + f"   Recommendation: {f.get('Recommendation')}" + Style.RESET_ALL)
                if i < len(findings):
                    print()
    else:
        print(Fore.GREEN + "✓ No findings — SSL/TLS configuration appears secure" + Style.RESET_ALL)

    print(Fore.CYAN + "════════════════════════════════════════════════════════════════" + Style.RESET_ALL)
    return findings


def check_ssl_tls(hostname: str) -> Dict[str, Any]:
    """
    Simple status checker used by main.py summary table.
    Returns a small dict:
      {
        "host": hostname,
        "https_supported": bool,
        "tls_version": str or None,
        "certificate_valid": bool,
        "certificate_expiry": "YYYY-MM-DD" or None,
        "days_until_expiry": int or None,
        "issuer": str or None,
        "error": None or error message
      }
    """
    result = {
        "host": hostname,
        "https_supported": False,
        "tls_version": None,
        "certificate_valid": False,
        "certificate_expiry": None,
        "days_until_expiry": None,
        "issuer": None,
        "error": None
    }
    try:
        # Verified handshake first
        cert_res, err = _get_cert_via_ssl_ctx(hostname, 443, verify=True, timeout=5)
        if err:
            result["error"] = err
            # try non-verified handshake to see if TLS exists
            nv_res, nv_err = _get_cert_via_ssl_ctx(hostname, 443, verify=False, timeout=5)
            if nv_res:
                result["https_supported"] = True
                result["tls_version"] = nv_res.get("tls_version")
            return result
        else:
            result["https_supported"] = True
            result["tls_version"] = cert_res.get("tls_version")
            cert = cert_res.get("cert") or {}
            # issuer
            try:
                issuer = dict(x[0] for x in cert.get("issuer", []))
                result["issuer"] = issuer.get("organizationName") or issuer.get("commonName")
            except Exception:
                result["issuer"] = None
            # expiry
            na = cert.get("notAfter")
            if na:
                try:
                    dt = datetime.datetime.strptime(na, "%b %d %H:%M:%S %Y %Z")
                except Exception:
                    try:
                        from email.utils import parsedate_to_datetime
                        dt = parsedate_to_datetime(na)
                    except Exception:
                        dt = None
                if dt:
                    result["certificate_expiry"] = dt.strftime("%Y-%m-%d")
                    result["days_until_expiry"] = (dt - datetime.datetime.utcnow()).days
                    result["certificate_valid"] = (result["days_until_expiry"] is not None and result["days_until_expiry"] > 0)
            return result
    except Exception as e:
        result["error"] = str(e)
        return result
