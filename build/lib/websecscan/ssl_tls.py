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

OPENSSL_TIMEOUT = 8  # seconds for openssl subprocess

# Silence SSL warnings for verify=False
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ----------------------
# OpenSSL subprocess helpers (used for protocol/cipher probing)
# ----------------------
def _run_openssl(host: str, port: int = 443,
                 proto_flag: Optional[str] = None,
                 timeout: int = OPENSSL_TIMEOUT) -> Optional[str]:
    # Build the command correctly: openssl s_client [proto_flag] -connect ...
    cmd = ["openssl", "s_client"]
    if proto_flag:
        cmd.append(proto_flag)
    cmd += ["-connect", f"{host}:{port}", "-servername", host]

    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = proc.communicate(input="Q\n", timeout=timeout)
        return (stdout or "") + (stderr or "")
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
    """Try common patterns to extract negotiated cipher from openssl output."""
    if not out:
        return None
    patterns = [
        r'Cipher\s*:\s*([^\s,]+)',
        r'New, TLSv[0-9.]+, Cipher is ([^\s,]+)',
        r'Cipher is ([^\s,]+)',
    ]
    for p in patterns:
        m = re.search(p, out)
        if m:
            return m.group(1).strip()
    return None


def _parse_server_temp_key_bits(out: str) -> Optional[int]:
    """Return DH temp key size in bits if present in openssl output."""
    if not out:
        return None
    m = re.search(r'Server Temp Key:\s*[^,]+,\s*([\d]+)\s*bits', out, re.IGNORECASE)
    if m:
        try:
            return int(m.group(1))
        except Exception:
            return None
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
    if any(x in c for x in ["RC4", "3DES", "DES", "EXPORT", "NULL", "ADH", "ANULL", "MD5"]):
        weak_reasons.append("Weak cipher or weak MAC (RC4/3DES/DES/EXPORT/NULL/MD5)")
    if not any(x in c for x in ["GCM", "POLY1305", "CHACHA20"]):
        weak_reasons.append("Non-AEAD cipher (prefer AES-GCM / ChaCha20-Poly1305)")
    return (len(weak_reasons) > 0), weak_reasons


def _probe_protocols_with_openssl(host: str, port: int = 443) -> Tuple[List[str], List[str], Optional[str]]:
    """
    Use openssl s_client with version flags to detect supported and deprecated protocols.
    Returns (supported_list, deprecated_list, note)
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
    for name, flag in protos.items():
        out = _run_openssl(host, port=port, proto_flag=flag)
        if not out:
            continue
        success = any(x in out for x in ["Cipher is", "Cipher :", "Verify return code: 0", "depth="])
        failure = any(x in out.lower() for x in ["wrong version", "no protocols available", "handshake failure", "no shared cipher", "alert handshake failure"])
        if success and not failure:
            if name in ("SSLv2", "SSLv3", "TLS 1.0", "TLS 1.1"):
                deprecated.append(name)
            else:
                supported.append(name)
    return supported, deprecated, None


def _probe_cipher_and_tempkey(host: str, port: int = 443, tls_version: Optional[str] = None) -> Dict[str, Any]:
    """
    Observe negotiated cipher and server temp key (DH) via openssl.
    Returns a dict with keys:
      negotiated_cipher, weak_ciphers (list), forward_secrecy (bool),
      dh_key_bits (int or None), openssl_available, openssl_output
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
    cipher = _parse_cipher_from_openssl(out or "")
    res["negotiated_cipher"] = cipher

    is_weak, reasons = _is_cipher_weak(cipher)
    if is_weak:
        res["weak_ciphers"].extend(reasons or [cipher or "Unknown"])

    c_upper = (cipher or "").upper()

    # Forward secrecy logic
    if tls_version == "TLSv1.3":
        res["forward_secrecy"] = True
    elif cipher and any(x in c_upper for x in ["ECDHE", "DHE"]):
        res["forward_secrecy"] = True
    else:
        res["forward_secrecy"] = False

    dhbits = _parse_server_temp_key_bits(out or "")
    res["dh_key_bits"] = dhbits
    if dhbits and dhbits < 2048:
        res["weak_ciphers"].append(f"Weak DH ({dhbits} bits)")

    return res


# ----------------------
# Certificate helpers (python ssl)
# ----------------------
def _get_cert_via_ssl_ctx(host: str, port: int = 443, verify: bool = True, timeout: int = 5) -> Tuple[Optional[dict], Optional[str]]:
    """
    Perform a TLS handshake using python ssl.
    If verify=True, perform normal validation.
    Returns ({"cert": cert_dict, "tls_version": tls_ver}, None) or (None, error_string).
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
                # TLS version string (may be None on some platforms)
                tls_ver = ss.version()
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
        for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT"):
            try:
                return datetime.datetime.strptime(v, fmt)
            except Exception:
                continue
        try:
            from email.utils import parsedate_to_datetime
            return parsedate_to_datetime(v)
        except Exception:
            return None

    return _parse_field(nb), _parse_field(na)


def get_certificate_details(host: str, port: int = 443) -> Optional[Dict[str, Any]]:
    """Return a structured dict of certificate details (issuer, sig alg, key, dates)."""
    try:
        res, err = _get_cert_via_ssl_ctx(host, port, verify=True, timeout=8)
        if err or not res:
            return None
        cert = res.get("cert") or {}
        parsed = {}
        # issuer
        issuer = "Unknown"
        try:
            iss = dict(x[0] for x in cert.get("issuer", []))
            issuer = iss.get("organizationName", iss.get("commonName", "Unknown"))
        except Exception:
            issuer = "Unknown"
        parsed["issuer"] = issuer

        # signature / key info via getpeercert binary if possible (best-effort)
        # Try to fetch binary cert via a non-verified handshake if necessary
        der = None
        try:
            # attempt to open a new socket and get binary form
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=6) as s:
                with ctx.wrap_socket(s, server_hostname=host) as ssock:
                    try:
                        der = ssock.getpeercert(binary_form=True)
                    except Exception:
                        der = None
        except Exception:
            der = None

        sig_alg = "Unknown"
        key_type = "Unknown"
        key_size = "Unknown"
        total_days = None

        if der:
            # Try to parse with openssl if available (best-effort)
            txt = None
            try:
                fd, path = tempfile.mkstemp(suffix=".der")
                with os.fdopen(fd, "wb") as f:
                    f.write(der)
                proc = subprocess.Popen(["openssl", "x509", "-in", path, "-inform", "DER", "-text", "-noout"],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                txt, _ = proc.communicate(timeout=6)
                if proc.returncode != 0:
                    txt = None
            except Exception:
                txt = None
            finally:
                try:
                    if 'path' in locals() and path and os.path.exists(path):
                        os.unlink(path)
                except Exception:
                    pass

            if txt:
                m = re.findall(r'Signature Algorithm:\s*([^\n]+)', txt)
                if m:
                    sig_alg = m[-1].strip()
                km = re.search(r'Public Key Algorithm:\s*([^\n]+)', txt)
                if km:
                    alg = km.group(1).strip().lower()
                    if "rsa" in alg:
                        key_type = "RSA"
                    elif "ec" in alg:
                        key_type = "ECDSA"
                    else:
                        key_type = alg
                ks = re.search(r'Public-Key:\s*\((\d+)\s*bit\)', txt)
                if ks:
                    key_size = ks.group(1)
                if key_type == "ECDSA":
                    cm = re.search(r'ASN1 OID:\s*([^\n]+)', txt)
                    if cm:
                        oid = cm.group(1).strip()
                        curve_map = {"prime256v1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521"}
                        key_type = f"ECDSA {curve_map.get(oid, oid)}"

        # dates
        nb_dt, na_dt = _parse_cert_dates(cert)
        valid_from = nb_dt.strftime("%Y-%m-%d") if nb_dt else None
        expiry = na_dt.strftime("%Y-%m-%d") if na_dt else None
        days_left = None
        if na_dt:
            days_left = (na_dt - datetime.datetime.utcnow()).days
            if nb_dt:
                total_days = (na_dt - nb_dt).days

        parsed.update({
            "signature_algorithm": sig_alg,
            "key_type": key_type,
            "key_size": key_size,
            "valid_from": valid_from,
            "expiry_date": expiry,
            "days_until_expiry": days_left,
            "total_validity_days": total_days,
            "certificate_valid": (days_left is not None and days_left > 0)
        })
        return parsed
    except Exception:
        return None


# ----------------------
# HTTP -> HTTPS redirect + HSTS check
# ----------------------
def check_http_redirect_and_hsts(target_url: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """
    Check http://host redirect -> https and detect HSTS header.
    Returns (http_to_https_redirect_bool, hsts_dict_or_None)
    """
    p = urllib.parse.urlparse(target_url)
    hostname = p.hostname
    if not hostname:
        return False, None

    http_url = f"http://{hostname}"
    if p.port:
        http_url = f"http://{hostname}:{p.port}"

    redirect_ok = False
    try:
        r = requests.get(http_url, timeout=5, allow_redirects=False)
        if r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("Location", "")
            if loc.startswith("https://"):
                redirect_ok = True
    except Exception:
        redirect_ok = False

    # HSTS: try HTTPS (verify=False so we can read header even on bad cert)
    hsts = None
    try:
        https_url = f"https://{hostname}"
        if p.port:
            https_url = f"https://{hostname}:{p.port}"
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
# Public API: run_ssl_check
# ----------------------
def run_ssl_check(target_url: str, verbose: bool = False) -> List[Dict[str, Any]]:
    """
    Run SSL/TLS checks and print friendly output.
    Returns a list of findings (dicts) suitable for integration with main.py.
    """
    findings: List[Dict[str, Any]] = []

    p = urllib.parse.urlparse(target_url)
    host = p.hostname
    port = p.port or 443

    if not host:
        print(Fore.RED + "[ERROR] Invalid URL." + Style.RESET_ALL)
        return []

    # Header
    print(Fore.CYAN + "\nSSL/TLS Security Analysis" + Style.RESET_ALL)
    print(Fore.MAGENTA + "═══════════════════════════════════════════════════════════════════════════════════════" + Style.RESET_ALL)
    print(Fore.WHITE + f"Target Host: {host}:{port}" + Style.RESET_ALL)
    print(Fore.YELLOW + "**********************************************************" + Style.RESET_ALL)

    # 1) Verified handshake (validate certificate)
    verification_error = None
    nonverified_error = None
    https_supported = False
    certificate_info = None
    tls_version = None

    cert_res, cert_err = _get_cert_via_ssl_ctx(host, port, verify=True, timeout=5)
    if cert_res and not cert_err:
        https_supported = True
        tls_version = cert_res.get("tls_version")
        certificate_info = get_certificate_details(host, port)
    else:
        verification_error = cert_err

    # 2) If verification failed, attempt non-verified handshake to detect TLS presence
    if not https_supported:
        nv_res, nv_err = _get_cert_via_ssl_ctx(host, port, verify=False, timeout=5)
        if nv_res and not nv_err:
            https_supported = True
            tls_version = nv_res.get("tls_version")
            # best-effort: do not re-run full cert parsing here
            certificate_info = certificate_info or {}
        else:
            nonverified_error = nv_err

    # 3) If no TLS detected -> print notice + findings and stop further probing
    if not https_supported:
        evidence = verification_error or nonverified_error or "TLS handshake failed"

        print(Fore.YELLOW + f"\n[Notice] No TLS/HTTPS service detected on {host}:{port}." + Style.RESET_ALL)
        print(Fore.YELLOW + "This usually means the server is serving plain HTTP (or another protocol) at this address/port," + Style.RESET_ALL)
        print(Fore.YELLOW + "so certificate, protocol and cipher details cannot be collected." + Style.RESET_ALL)
        print(Fore.YELLOW + f"Detected error: {evidence}" + Style.RESET_ALL)
        print(Fore.YELLOW + "**********************************************************" + Style.RESET_ALL)

        finding = {
            "Category": "SSL/TLS",
            "Severity": "High",
            "Title": "HTTPS Not Supported",
            "_item_short": "https-not-supported",
            "Current Value": f"No TLS listener detected on {host}:{port}.",
            "Evidence": evidence,
            "Recommendation": "Enable HTTPS and configure a valid certificate. Ensure a TLS listener is present on port 443 (or the configured port)."
        }
        findings.append(finding)

        # Print risk rating block (High + CVSS 9.8 as requested)
        print(Fore.WHITE + "\nRisk Rating:" + Style.RESET_ALL)
        print(Fore.WHITE + "Severity: High" + Style.RESET_ALL)
        print(Fore.WHITE + "CVSS: 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)" + Style.RESET_ALL)
        print(Fore.WHITE + "\nFindings:" + Style.RESET_ALL)
        print(Fore.CYAN + "`" * 88 + Style.RESET_ALL)

        # Format the single finding exactly as requested
        print(Fore.WHITE + "1. HTTPS Not Supported" + Style.RESET_ALL)
        print(Fore.WHITE + f"   Current Value: {finding['Current Value']}" + Style.RESET_ALL)
        print(Fore.WHITE + f"   Evidence: {finding['Evidence']}" + Style.RESET_ALL)
        print(Fore.WHITE + f"   Recommendation: {finding['Recommendation']}" + Style.RESET_ALL)

        print(Fore.MAGENTA + "═══════════════════════════════════════════════════════════════════════════════════════" + Style.RESET_ALL)
        return findings

    # 4) TLS present -> proceed to protocol/cipher probing (use openssl if available)
    supported, deprecated, proto_note = _probe_protocols_with_openssl(host, port)
    cipher_probe = _probe_cipher_and_tempkey(host, port, tls_version=tls_version)
    negotiated_cipher = cipher_probe.get("negotiated_cipher")
    forward_secrecy = cipher_probe.get("forward_secrecy", False)
    weak_ciphers = cipher_probe.get("weak_ciphers", [])

    # 5) Collect findings based on results

    # Certificate validation error (if any) is High
    if verification_error:
        findings.append({
            "Category": "SSL/TLS",
            "Severity": "High",
            "Title": "SSL Certificate Validity – Expired / Not Yet Valid / Mismatch",
            "_item_short": "ssl-cert-invalid",
            "Current Value": f"Status: validation error ({verification_error})",
            "Evidence": verification_error,
            "Recommendation": "Install a valid SSL certificate from a trusted CA and ensure the certificate matches the host name."
        })

    # Protocols: deprecated -> Medium
    if deprecated:
        findings.append({
            "Category": "SSL/TLS",
            "Severity": "Medium",
            "Title": "Use of Weak Protocol Version",
            "_item_short": "weak-protocol",
            "Current Value": f"{', '.join(deprecated)}",
            "Evidence": f"Deprecated protocols detected: {', '.join(deprecated)}",
            "Recommendation": "Disable deprecated versions. Only allow TLS 1.2 and TLS 1.3."
        })

    # Weak ciphers -> Medium
    if weak_ciphers:
        findings.append({
            "Category": "SSL/TLS",
            "Severity": "Medium",
            "Title": "Use of Weak Cipher Suites",
            "_item_short": "weak-cipher",
            "Current Value": ", ".join(weak_ciphers),
            "Evidence": f"Weak ciphers detected: {', '.join(weak_ciphers)}",
            "Recommendation": "Remove weak cipher suites and enable modern AEAD suites (AES-GCM, ChaCha20-Poly1305) with ECDHE."
        })

    # Missing forward secrecy or weak DH bits
    dh_bits = cipher_probe.get("dh_key_bits")
    if (negotiated_cipher and not forward_secrecy) or (dh_bits is not None and dh_bits < 2048):
        if negotiated_cipher and not forward_secrecy:
            findings.append({
                "Category": "SSL/TLS",
                "Severity": "Medium",
                "Title": "Missing Forward Secrecy",
                "_item_short": "missing-forward-secrecy",
                "Current Value": f"Negotiated Cipher: {negotiated_cipher}\nForward Secrecy: No",
                "Evidence": f"Negotiated cipher: {negotiated_cipher}",
                "Recommendation": "Enable ECDHE/DHE cipher suites to provide forward secrecy (ECDHE preferred)."
            })
        if dh_bits and dh_bits < 2048:
            findings.append({
                "Category": "SSL/TLS",
                "Severity": "Medium",
                "Title": "Weak Diffie-Hellman Key Size",
                "_item_short": "weak-dh",
                "Current Value": f"DH Key Size: {dh_bits} bits",
                "Evidence": f"Temporary DH key length reported: {dh_bits} bits",
                "Recommendation": "Enforce DH >= 2048 bits or use ECDHE (X25519/P-256)."
            })

    # Certificate details: expiry / long validity / signature algorithm
    cert = certificate_info
    if cert:
        days_left = cert.get("days_until_expiry")
        total_days = cert.get("total_validity_days")
        sig_alg = cert.get("signature_algorithm")
        expiry_date = cert.get("expiry_date")

        if days_left is not None and 0 <= days_left < 30:
            findings.append({
                "Category": "SSL/TLS",
                "Severity": "Medium",
                "Title": "SSL Certificate Validity – Expiry",
                "_item_short": "ssl-cert-expired",
                "Current Value": f"Expiry Date: {expiry_date}\nDays Until Expiry: {days_left}",
                "Evidence": f"Days until expiry: {days_left}",
                "Recommendation": "Renew certificate before expiry to avoid service interruption."
            })

        if total_days and total_days > 397:
            findings.append({
                "Category": "SSL/TLS",
                "Severity": "Medium",
                "Title": "SSL Certificate Validity – Duration Too Long",
                "_item_short": "ssl-cert-validity-too-long",
                "Current Value": f"Certificate Validity: {total_days} days",
                "Evidence": f"Total validity days: {total_days}",
                "Recommendation": "Replace certificate with one valid for ≤ 397 days."
            })

        if sig_alg and re.search(r"sha1|md5", str(sig_alg), re.IGNORECASE):
            findings.append({
                "Category": "SSL/TLS",
                "Severity": "Medium",
                "Title": "Weak Certificate Signature Algorithm",
                "_item_short": "weak-signature",
                "Current Value": str(sig_alg),
                "Evidence": f"Signature algorithm: {sig_alg}",
                "Recommendation": "Use certificates signed with SHA-256 or stronger."
            })

     # HTTPS support: redirect & HSTS
    redirect_ok, hsts = check_http_redirect_and_hsts(target_url)
    if not redirect_ok:
        findings.append({
            "Category": "SSL/TLS",
            "Severity": "Medium",
            "Title": "HTTPS Not Enforced (No HTTP → HTTPS Redirect)",
            "_item_short": "no-redirect",
            "Current Value": "Plain HTTP requests are not redirected to HTTPS (or redirect not observed).",
            "Evidence": "no-redirect",
            "Recommendation": "Configure the server to redirect all HTTP traffic to HTTPS (301/307) and use HSTS."
        })

    if isinstance(hsts, dict) and not hsts.get("present"):
        findings.append({
            "Category": "SSL/TLS",
            "Severity": "Medium",
            "Title": "Missing HSTS (HTTP Strict Transport Security)",
            "_item_short": "no-hsts",
            "Current Value": "HSTS header not present",
            "Evidence": "no-hsts",
            "Recommendation": "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
        })

    # ---------------------------
    # Print friendly summary blocks (certificate / protocol / cipher / https)
    # ---------------------------
    if verbose:
       # Protocols
        print(Fore.WHITE + "Protocol Versions:" + Style.RESET_ALL)
        proto_supported_display = ", ".join(supported) if supported else ("Unknown (openssl missing or probe failed)" if _openssl_available() is False else "Unknown")
        print(Fore.WHITE + f"  Supported: {proto_supported_display}" + Style.RESET_ALL)
        if deprecated:
            print(Fore.RED + f"  Deprecated Versions Detected: {', '.join(deprecated)}" + Style.RESET_ALL)

        # Certificate block
        if cert:
            print(Fore.WHITE + "\nSSL Certificate Information:" + Style.RESET_ALL)
            print(Fore.WHITE + f"  Issuer: {cert.get('issuer','Unknown')}" + Style.RESET_ALL)
            print(Fore.WHITE + f"  Signature Algorithm: {cert.get('signature_algorithm','Unknown')}" + Style.RESET_ALL)
            key_type = cert.get('key_type', 'Unknown')
            key_size = cert.get('key_size', 'Unknown')
            keyinfo = key_type + (f" {key_size}-bit" if key_size and key_size != 'Unknown' else "")
            print(Fore.WHITE + f"  Key Type / Size: {keyinfo}" + Style.RESET_ALL)
            print(Fore.WHITE + f"  Valid From: {cert.get('valid_from','N/A')}" + Style.RESET_ALL)
            print(Fore.WHITE + f"  Expiry Date: {cert.get('expiry_date','N/A')}" + Style.RESET_ALL)
            print(Fore.WHITE + f"  Days Until Expiry: {cert.get('days_until_expiry')}" + Style.RESET_ALL)
        else:
            if verification_error:
                print(Fore.YELLOW + "\nSSL Certificate Information: Unable to obtain certificate details due to validation error." + Style.RESET_ALL)
                print(Fore.YELLOW + f"  Validation error: {verification_error}" + Style.RESET_ALL)

        # Cipher
        print(Fore.WHITE + "\nCipher Suites:" + Style.RESET_ALL)
        print(Fore.WHITE + f"  Negotiated Cipher: {negotiated_cipher if negotiated_cipher else 'N/A'}" + Style.RESET_ALL)
        if weak_ciphers:
            print(Fore.RED + f"  Weak Ciphers Detected: {', '.join(weak_ciphers)}" + Style.RESET_ALL)
        print(Fore.WHITE + f"  Forward Secrecy: {'Yes' if forward_secrecy else 'No'}" + Style.RESET_ALL)
        if cipher_probe.get("openssl_available") is False:
            print(Fore.YELLOW + "  Note: openssl binary not found; protocol/cipher probing was limited." + Style.RESET_ALL)

        # HTTPS support summary
        print(Fore.WHITE + "\nHTTPS Support:" + Style.RESET_ALL)
        print(Fore.WHITE + f"  HTTPS Supported: {'Yes' if https_supported else 'No'}" + Style.RESET_ALL)
        print(Fore.WHITE + f"  HTTP → HTTPS Redirect: {'Yes' if redirect_ok else 'No'}" + Style.RESET_ALL)
        if isinstance(hsts, dict):
            print(Fore.WHITE + ("  HSTS: Present" if hsts.get("present") else "  HSTS: Not Present") + Style.RESET_ALL)
        else:
            print(Fore.WHITE + "  HSTS: Unknown" + Style.RESET_ALL)

        print(Fore.YELLOW + "**********************************************************" + Style.RESET_ALL)

    # ---------------------------
    # Final risk rating block (only print if there are findings)
    # ---------------------------
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
            print(Fore.WHITE + "\nRisk Rating" + Style.RESET_ALL)
            print(Fore.WHITE + f"Severity: {overall}" + Style.RESET_ALL)
            if overall_cvss:
                print(Fore.WHITE + f"CVSS: {overall_cvss}" + Style.RESET_ALL)
            print(Fore.WHITE + "\nFindings:" + Style.RESET_ALL)
            print(Fore.CYAN + "`" * 88 + Style.RESET_ALL)

            for i, f in enumerate(findings, start=1):
                print(Fore.WHITE + f"{i}. {f.get('Title')}" + Style.RESET_ALL)
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
        print(Fore.GREEN + "✓ SSL/TLS configuration appears secure" + Style.RESET_ALL)

    print(Fore.MAGENTA + "═══════════════════════════════════════════════════════════════════════════════════════" + Style.RESET_ALL)
    return findings


# ----------------------
# Lightweight status function for main.py summary table
# ----------------------
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
        cert_res, err = _get_cert_via_ssl_ctx(hostname, 443, verify=True, timeout=5)
        if err:
            result["error"] = err
            nv_res, nv_err = _get_cert_via_ssl_ctx(hostname, 443, verify=False, timeout=5)
            if nv_res:
                result["https_supported"] = True
                result["tls_version"] = nv_res.get("tls_version")
            return result
        else:
            result["https_supported"] = True
            result["tls_version"] = cert_res.get("tls_version")
            cert = cert_res.get("cert") or {}
            try:
                issuer = dict(x[0] for x in cert.get("issuer", []))
                result["issuer"] = issuer.get("organizationName") or issuer.get("commonName")
            except Exception:
                result["issuer"] = None
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