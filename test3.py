'''
# vulnerability_definitions.py
"""
Vulnerability Definitions Database

Contains detailed information (Description, Impact, CVSS) for each vulnerability category.
This data enriches findings before report generation.
"""

VULNERABILITY_DEFINITIONS = {
    "HTTP Security Headers": {
    "Description": """HTTP security headers provide yet another layer of security by helping to mitigate attacks and security vulnerabilities. Whenever a browser requests a page from a web server, the server responds with the content along with HTTP response headers. With the misconfigured or missing of HTTP security headers, the attackers may gain information from the data which may lead to various of attacks such as clickjacking, cross-site scripting (XSS) and others attacks as well.""",
    "CVSS": "3.1 (AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N)",

        # Per-header definitions used to build dynamic Impact/Recommendation
        "HeaderDetails": {
            "Strict-Transport-Security": {
                "Impact": "Missing Strict-Transport-Security allows downgrade attacks and enables interception of traffic as this header lets a website tell browsers that it should only be accessed using HTTPS, instead of using HTTP.",
                "Recommendation": "Enable HSTS with an appropriate max-age and includeSubDomains; consider preload where suitable."
            },
            "X-Frame-Options": {
                "Impact": "Missing X-Frame-Options allows clickjacking attacks.",
                "Recommendation": "Set X-Frame-Options to SAMEORIGIN or DENY to prevent framing by untrusted sites."
            },
            "X-Content-Type-Options": {
                "Impact": "Missing or insecure X-Content-Type-Options allows MIME-sniffing attacks, increasing XSS risk.",
                "Recommendation": "Set X-Content-Type-Options: nosniff on all responses."
            },
            "X-XSS-Protection": {
                "Impact": "Missing X-XSS-Protection increases exposure to reflected XSS attacks in older browsers.",
                "Recommendation": "Enable 'Content Security Policy' (CSP) that disables the use of inline JavaScript. Disable the 'X-XSS-Protection' by setting the following response header: 'X-XSS-Protection: 0'"
            },
            "Content-Security-Policy": {
                "Impact": "Missing Content-Security-Policy significantly increases exploitability of XSS vulnerabilities.",
                "Recommendation": "Set Content-Security-Policy: default-src 'self'; frame-ancestors 'none' to restrict script, frame, and resource loading sources."
            },
            "Cache-Control": {
                "Impact": "Missing or weak Cache-Control may expose sensitive information stored in browser cache.",
                "Recommendation": "Use Cache-Control: no-store,no-cache for sensitive pages to prevent caching."
            },
            "Referrer-Policy": {
                "Impact": "Missing Referrer-Policy may cause the browser to leak sensitive URL information to external sites during navigation.",
                "Recommendation": "Set Referrer-Policy: strict-origin-when-cross-origin to limit referrer data sent to external origins."
            },
            "Cross-Origin-Opener-Policy": {
                "Impact": "Missing COOP allows external sites to open and interact with the browsing context, increasing risks such as cross-origin attacks and tab-nabbing.",
                "Recommendation": "Set Cross-Origin-Opener-Policy: same-origin to isolate the browsing context and enhance security."
            },
            "Cross-Origin-Embedder-Policy": {
                "Impact": "Missing COEP may allow the application to load untrusted cross-origin resources that are not opt-in, reducing the protection against cross-site data leaks.",
                "Recommendation": "Set Cross-Origin-Embedder-Policy: require-corp to ensure only secure, explicitly allowed resources can be embedded."
            },
            "Cross-Origin-Resource-Policy": {
                "Impact": "Missing CORP may allow other websites to load the resources cross-origin, potentially exposing sensitive data.",
                "Recommendation": "Set Cross-Origin-Resource-Policy: same-site to restrict resource usage to the same site."
            }
        }
    },
    
    "Unsafe HTTP Methods Enabled": {
        "Description": """HTTP offers a number of methods that can be used to perform actions on the web server. Many of these methods are designed to aid developers in deploying and testing HTTP applications. These HTTP methods can be used for nefarious purposes if the web server is misconfigured.

Some of these methods can potentially pose a security risk for a web application, as they allow a hacker to modify the files stored on the web server and, in some scenarios, steal the credentials of legitimate users. More specifically, the methods that should be disabled are the following:

- OPTIONS: This method is a diagnostic method which is mainly used for debugging purpose. It provides a list of the methods that are supported by the web server.
- TRACE: This method simply echoes back to the client whatever string has been sent to the server, and is used mainly for debugging purposes.
- PUT: This method allows a client to upload new files on the web server. An attacker can exploit it by uploading malicious files.
- DELETE: This method allows a client to delete a file on the web server. An attacker can exploit it as a very simple and direct way to deface a web site or to mount a Denial of Service (DoS) attack.
- DEBUG: This method is used for debugging purposes. It allows developers to diagnose and troubleshoot issues by providing detailed information about the server's operation.""",
        "CVSS": "5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)",
        "Impact": """1. Sensitive server information can be retrieved and used by the attacker to plan further attacks and techniques.
2. Include content, scripts, binaries or images from potentially malicious sources.""",
        "Recommendation": "Disable methods such as OPTIONS, TRACE, PUT, DELETE or DEBUG."
    },
    
    "Security Headers": {
        "Description": """HTTP security headers are a fundamental part of website security. Upon implementation, they protect you against the types of attacks that your site is most likely to come across. These headers protect against XSS, code injection, clickjacking, and other common attacks.

Missing or misconfigured security headers can leave applications vulnerable to various client-side attacks including cross-site scripting (XSS), clickjacking, and information leakage.""",
        "CVSS": "3.1 (AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N)",
        "Impact": """1. Increased risk of cross-site scripting (XSS) attacks
2. Vulnerability to clickjacking attacks
3. Potential for MIME-type sniffing attacks
4. Exposure to man-in-the-middle attacks (if HSTS is missing)
5. Browser-based security features not properly utilized""",
        "Recommendation": """Implement the following security headers with appropriate values:
- Content-Security-Policy: default-src 'self'; frame-ancestors 'none'
- Strict-Transport-Security: max-age=31536000; includeSubDomains
- X-Frame-Options: SAMEORIGIN / DENY
- X-Content-Type-Options: nosniff
- Referrer-Policy: strict-origin-when-cross-origin
- Permissions-Policy: Configure based on required features"""
    },
    
    "Server Information": {
        "Description": """Web servers often expose detailed version information in HTTP response headers (Server, X-Powered-By) or error pages. This information disclosure can help attackers identify known vulnerabilities specific to the software versions in use.

Exposing server software versions, framework details, or technology stack information provides attackers with valuable reconnaissance data to craft targeted exploits.""",
        "CVSS": "5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)",
        "Impact": """1. Attackers can identify specific software versions and search for known vulnerabilities
2. Technology stack information helps in crafting targeted attacks
3. Reduces the effort required for reconnaissance phase of attacks
4. May reveal end-of-life or outdated software in use""",
        "Recommendation": """1. Remove or obfuscate the Server header
2. Remove X-Powered-By and similar headers
3. Customize error pages to avoid exposing version information
4. Use reverse proxies or web application firewalls to mask backend technologies
5. Regularly update server software to latest secure versions"""
    },
    
    "Cookie Security": {
        "Description": """Cookies are small pieces of data stored by the browser that can contain sensitive information like session tokens, user preferences, and authentication data. Improperly configured cookies can be intercepted, manipulated, or stolen by attackers.

Cookie security attributes (Secure, HttpOnly, SameSite) are critical defenses against common web attacks including session hijacking, cross-site scripting (XSS), and cross-site request forgery (CSRF).""",
        "CVSS": "6.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N)",
        "Impact": """1. Session hijacking through cookie theft
2. Cross-site scripting (XSS) attacks can access sensitive cookies
3. Man-in-the-middle attacks can intercept cookies over insecure connections
4. Cross-site request forgery (CSRF) attacks
5. Unauthorized access to user accounts and sensitive data""",
        "Recommendation": """Set appropriate cookie attributes:
- Secure: Ensure cookies are only transmitted over HTTPS
- HttpOnly: Prevent JavaScript access to cookies
- SameSite: Set to 'Strict' or 'Lax' to prevent CSRF attacks
- Domain and Path: Scope cookies appropriately
- Expiration: Set reasonable expiration times for session cookies"""
    },
    
    "CORS Security": {
        "Description": """Cross-Origin Resource Sharing (CORS) is a mechanism that allows restricted resources on a web page to be requested from another domain. Misconfigured CORS policies can allow malicious websites to access sensitive data or perform actions on behalf of authenticated users.

An overly permissive CORS policy (especially using wildcards with credentials) can expose the application to data theft and unauthorized actions.""",
        "CVSS": "7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)",
        "Impact": """1. Unauthorized access to sensitive API endpoints from malicious origins
2. Data exfiltration to attacker-controlled domains
3. Theft of authentication tokens and session information
4. Ability to perform authenticated actions on behalf of victims
5. Bypass of same-origin policy protections""",
        "Recommendation": """1. Avoid using wildcard (*) in Access-Control-Allow-Origin with credentials
2. Explicitly whitelist trusted origins
3. Do not reflect Origin header without validation
4. Use Access-Control-Allow-Credentials: true only when necessary
5. Implement proper authentication and authorization checks server-side
6. Regularly audit CORS configurations"""
    },
    
    "Directory Exposure": {
        "Description": """Directory exposure occurs when web servers are misconfigured to display directory listings or when sensitive files and directories are accessible without proper authentication. This can reveal the application's file structure, backup files, configuration files, and other sensitive information.

Common exposed items include .git directories, backup files, configuration files, and development/testing resources that should not be publicly accessible.""",
        "CVSS": "5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)",
        "Impact": """1. Exposure of source code and sensitive configuration data
2. Discovery of backup files containing sensitive information
3. Revelation of application structure aiding further attacks
4. Access to credentials, API keys, or database connection strings
5. Discovery of hidden administrative interfaces
6. Information useful for social engineering attacks""",
        "Recommendation": """1. Disable directory listing in web server configuration
2. Remove or restrict access to .git, .svn, and other version control directories
3. Delete backup files, old code, and testing resources from production
4. Implement proper access controls for administrative areas
5. Use robots.txt carefully (does not provide security)
6. Regularly scan for exposed sensitive files
7. Implement proper file permissions on the server"""
    },
    
    "Path Traversal": {
        "Description": """Path traversal (also known as directory traversal) is a vulnerability that allows attackers to access files and directories stored outside the web root folder. By manipulating file path references using sequences like '../', attackers can break out of the intended directory structure.

This vulnerability typically occurs when user input is used to construct file paths without proper validation, allowing access to sensitive system files, application configuration, or other restricted resources.""",
        "CVSS": "7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)",
        "Impact": """1. Unauthorized access to sensitive files (passwords, configuration files, source code)
2. Exposure of system files (/etc/passwd, web server configs)
3. Access to application source code revealing business logic
4. Potential for privilege escalation
5. Information gathering for further attacks
6. In severe cases, ability to read private keys or credentials""",
        "Recommendation": """1. Validate and sanitize all user inputs used in file operations
2. Use whitelist approach for allowed files/paths
3. Implement proper access controls at the application level
4. Use built-in framework functions for file operations that handle path normalization
5. Run web server with minimal privileges
6. Disable dangerous functions in production (if using PHP: disable readfile, file_get_contents for user input)
7. Use chroot jails or containers to limit file system access
8. Regularly test for path traversal vulnerabilities"""
    },
    
    "SSL/TLS": {
        "Description": """SSL/TLS (Secure Sockets Layer/Transport Layer Security) provides encryption for data in transit between clients and servers. Weak SSL/TLS configurations, outdated protocols, weak ciphers, or certificate issues can expose communications to interception and manipulation.

Common issues include expired certificates, self-signed certificates in production, support for deprecated protocols (SSLv3, TLS 1.0, TLS 1.1), weak cipher suites, and missing security features like HSTS.""",
        "CVSS": "7.4 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N)",
        "Impact": """1. Man-in-the-middle attacks allowing traffic interception
2. Exposure of sensitive data transmitted over insecure connections
3. Session hijacking through unencrypted session tokens
4. Credential theft during authentication
5. Loss of user trust due to browser security warnings
6. Compliance violations (PCI-DSS, HIPAA, GDPR)
7. Vulnerability to known attacks (BEAST, POODLE, CRIME)""",
        "Recommendation": """1. Use valid certificates from trusted Certificate Authorities
2. Disable SSLv3, TLS 1.0, and TLS 1.1 - use TLS 1.2 or TLS 1.3
3. Configure strong cipher suites and disable weak ciphers
4. Implement HTTP Strict Transport Security (HSTS)
5. Enable Perfect Forward Secrecy (PFS)
6. Regularly monitor certificate expiration dates
7. Implement certificate pinning for mobile applications
8. Use tools like SSL Labs to test configuration
9. Keep OpenSSL/TLS libraries updated"""
    }
}


def enrich_finding_with_details(finding: dict) -> dict:
    """
    Enrich a finding dictionary with detailed information from the definitions database.
    
    Args:
        finding: A finding dict with at least 'Category' field
        
    Returns:
        Enriched finding dict with Description, CVSS, Impact, and Recommendation
    """
    category = finding.get("Category", "")
    
    # Try exact match first
    vuln_def = VULNERABILITY_DEFINITIONS.get(category)
    
    # If no exact match, try partial matching for common cases
    if not vuln_def:
        for def_category, details in VULNERABILITY_DEFINITIONS.items():
            if category.lower() in def_category.lower() or def_category.lower() in category.lower():
                vuln_def = details
                break
    
    # If still no match, provide generic information
    if not vuln_def:
        vuln_def = {
            "Description": finding.get("Description", "Security misconfiguration detected."),
            "CVSS": "N/A",
            "Impact": "This configuration may pose a security risk to the application.",
            "Recommendation": finding.get("Recommendation", "Review and remediate this security issue.")
        }
    
    # Create enriched finding
    enriched = finding.copy()
    
    # Add missing fields from definitions (don't override existing ones)
    if "Description" not in enriched or not enriched["Description"]:
        enriched["Description"] = vuln_def["Description"]
    
    if "CVSS" not in enriched or not enriched["CVSS"]:
        enriched["CVSS"] = vuln_def["CVSS"]
    
    if "Impact" not in enriched or not enriched["Impact"]:
        enriched["Impact"] = vuln_def["Impact"]
    
    if "Recommendation" not in enriched or not enriched["Recommendation"]:
        enriched["Recommendation"] = vuln_def["Recommendation"]
    
    return enriched


def enrich_all_findings(findings: list) -> list:
    """
    Enrich all findings in a list with detailed vulnerability information.
    
    Args:
        findings: List of finding dicts
        
    Returns:
        List of enriched finding dicts
    """
    return [enrich_finding_with_details(f) for f in findings]
'''


# vulnerability_definitions.py (test3.py)
"""
Vulnerability Definitions Database

Contains detailed information (Description, Impact, CVSS) for each vulnerability category.
This data enriches findings before report generation.
"""

VULNERABILITY_DEFINITIONS = {
    "HTTP Security Headers": {
        "Description": """HTTP security headers provide yet another layer of security by helping to mitigate attacks and security vulnerabilities. Whenever a browser requests a page from a web server, the server responds with the content along with HTTP response headers. With the misconfigured or missing of HTTP security headers, the attackers may gain information from the data which may lead to various of attacks such as clickjacking, cross-site scripting (XSS) and others attacks as well.""",
        "CVSS": "3.1 (AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N)",

        # Per-header definitions used to build dynamic Impact/Recommendation
        "HeaderDetails": {
            "Strict-Transport-Security": {
                "Impact": "Missing Strict-Transport-Security allows downgrade attacks and enables interception of traffic as this header lets a website tell browsers that it should only be accessed using HTTPS, instead of using HTTP.",
                "Recommendation": "Enable HSTS with an appropriate max-age and includeSubDomains; consider preload where suitable."
            },
            "X-Frame-Options": {
                "Impact": "Missing X-Frame-Options allows clickjacking attacks.",
                "Recommendation": "Set X-Frame-Options to SAMEORIGIN or DENY to prevent framing by untrusted sites."
            },
            "X-Content-Type-Options": {
                "Impact": "Missing or insecure X-Content-Type-Options allows MIME-sniffing attacks, increasing XSS risk.",
                "Recommendation": "Set X-Content-Type-Options: nosniff on all responses."
            },
            "X-XSS-Protection": {
                "Impact": "Missing X-XSS-Protection increases exposure to reflected XSS attacks in older browsers.",
                "Recommendation": "Enable 'Content Security Policy' (CSP) that disables the use of inline JavaScript. Disable the 'X-XSS-Protection' by setting the following response header: 'X-XSS-Protection: 0'"
            },
            "Content-Security-Policy": {
                "Impact": "Missing Content-Security-Policy significantly increases exploitability of XSS vulnerabilities.",
                "Recommendation": "Set Content-Security-Policy: default-src 'self'; frame-ancestors 'none' to restrict script, frame, and resource loading sources."
            },
            "Cache-Control": {
                "Impact": "Missing or weak Cache-Control may expose sensitive information stored in browser cache.",
                "Recommendation": "Use Cache-Control: no-store,no-cache for sensitive pages to prevent caching."
            },
            "Referrer-Policy": {
                "Impact": "Missing Referrer-Policy may cause the browser to leak sensitive URL information to external sites during navigation.",
                "Recommendation": "Set Referrer-Policy: strict-origin-when-cross-origin to limit referrer data sent to external origins."
            },
            "Cross-Origin-Opener-Policy": {
                "Impact": "Missing COOP allows external sites to open and interact with the browsing context, increasing risks such as cross-origin attacks and tab-nabbing.",
                "Recommendation": "Set Cross-Origin-Opener-Policy: same-origin to isolate the browsing context and enhance security."
            },
            "Cross-Origin-Embedder-Policy": {
                "Impact": "Missing COEP may allow the application to load untrusted cross-origin resources that are not opt-in, reducing the protection against cross-site data leaks.",
                "Recommendation": "Set Cross-Origin-Embedder-Policy: require-corp to ensure only secure, explicitly allowed resources can be embedded."
            },
            "Cross-Origin-Resource-Policy": {
                "Impact": "Missing CORP may allow other websites to load the resources cross-origin, potentially exposing sensitive data.",
                "Recommendation": "Set Cross-Origin-Resource-Policy: same-site to restrict resource usage to the same site."
            }
        }
    },
    
    "Unsafe HTTP Methods Enabled": {
        "Description": """HTTP offers a number of methods that can be used to perform actions on the web server. Many of these methods are designed to aid developers in deploying and testing HTTP applications. These HTTP methods can be used for nefarious purposes if the web server is misconfigured.

Some of these methods can potentially pose a security risk for a web application, as they allow a hacker to modify the files stored on the web server and, in some scenarios, steal the credentials of legitimate users. More specifically, the methods that should be disabled are the following:

- OPTIONS: This method is a diagnostic method which is mainly used for debugging purpose. It provides a list of the methods that are supported by the web server.
- TRACE: This method simply echoes back to the client whatever string has been sent to the server, and is used mainly for debugging purposes.
- PUT: This method allows a client to upload new files on the web server. An attacker can exploit it by uploading malicious files.
- DELETE: This method allows a client to delete a file on the web server. An attacker can exploit it as a very simple and direct way to deface a web site or to mount a Denial of Service (DoS) attack.
- DEBUG: This method is used for debugging purposes. It allows developers to diagnose and troubleshoot issues by providing detailed information about the server's operation.""",
        "CVSS": "5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)",
        "Impact": """1. Sensitive server information can be retrieved and used by the attacker to plan further attacks and techniques.
2. Include content, scripts, binaries or images from potentially malicious sources.""",
        "Recommendation": "Disable methods such as OPTIONS, TRACE, PUT, DELETE or DEBUG."
    },
    
    
    "Server Information": {
        "Description": """Web servers often expose detailed version information in HTTP response headers (Server, X-Powered-By) or error pages. This information disclosure can help attackers identify known vulnerabilities specific to the software versions in use.

Exposing server software versions, framework details, or technology stack information provides attackers with valuable reconnaissance data to craft targeted exploits.""",
        "CVSS": "5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)",
        "Impact": """1. Attackers can identify specific software versions and search for known vulnerabilities
2. Technology stack information helps in crafting targeted attacks
3. Reduces the effort required for reconnaissance phase of attacks
4. May reveal end-of-life or outdated software in use""",
        "Recommendation": """1. Remove or obfuscate the Server header
2. Remove X-Powered-By and similar headers
3. Customize error pages to avoid exposing version information
4. Use reverse proxies or web application firewalls to mask backend technologies
5. Regularly update server software to latest secure versions"""
    },
    
    "Cookie Security": {
        "Description": """Cookies are small pieces of data stored by the browser that can contain sensitive information like session tokens, user preferences, and authentication data. Improperly configured cookies can be intercepted, manipulated, or stolen by attackers.

Cookie security attributes (Secure, HttpOnly, SameSite) are critical defenses against common web attacks including session hijacking, cross-site scripting (XSS), and cross-site request forgery (CSRF).""",
        "CVSS": "6.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N)",
        "Impact": """1. Session hijacking through cookie theft
2. Cross-site scripting (XSS) attacks can access sensitive cookies
3. Man-in-the-middle attacks can intercept cookies over insecure connections
4. Cross-site request forgery (CSRF) attacks
5. Unauthorized access to user accounts and sensitive data""",
        "Recommendation": """Set appropriate cookie attributes:
- Secure: Ensure cookies are only transmitted over HTTPS
- HttpOnly: Prevent JavaScript access to cookies
- SameSite: Set to 'Strict' or 'Lax' to prevent CSRF attacks
- Domain and Path: Scope cookies appropriately
- Expiration: Set reasonable expiration times for session cookies"""
    },
    
    "CORS Security": {
        "Description": """Cross-Origin Resource Sharing (CORS) is a mechanism that allows restricted resources on a web page to be requested from another domain. Misconfigured CORS policies can allow malicious websites to access sensitive data or perform actions on behalf of authenticated users.

An overly permissive CORS policy (especially using wildcards with credentials) can expose the application to data theft and unauthorized actions.""",
        "CVSS": "7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)",
        "Impact": """1. Unauthorized access to sensitive API endpoints from malicious origins
2. Data exfiltration to attacker-controlled domains
3. Theft of authentication tokens and session information
4. Ability to perform authenticated actions on behalf of victims
5. Bypass of same-origin policy protections""",
        "Recommendation": """1. Avoid using wildcard (*) in Access-Control-Allow-Origin with credentials
2. Explicitly whitelist trusted origins
3. Do not reflect Origin header without validation
4. Use Access-Control-Allow-Credentials: true only when necessary
5. Implement proper authentication and authorization checks server-side
6. Regularly audit CORS configurations"""
    },
    
    "Directory Exposure": {
        "Description": """Directory exposure occurs when web servers are misconfigured to display directory listings or when sensitive files and directories are accessible without proper authentication. This can reveal the application's file structure, backup files, configuration files, and other sensitive information.

Common exposed items include .git directories, backup files, configuration files, and development/testing resources that should not be publicly accessible.""",
        "CVSS": "5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)",
        "Impact": """1. Exposure of source code and sensitive configuration data
2. Discovery of backup files containing sensitive information
3. Revelation of application structure aiding further attacks
4. Access to credentials, API keys, or database connection strings
5. Discovery of hidden administrative interfaces
6. Information useful for social engineering attacks""",
        "Recommendation": """1. Disable directory listing in web server configuration
2. Remove or restrict access to .git, .svn, and other version control directories
3. Delete backup files, old code, and testing resources from production
4. Implement proper access controls for administrative areas
5. Use robots.txt carefully (does not provide security)
6. Regularly scan for exposed sensitive files
7. Implement proper file permissions on the server"""
    },
    
    "Path Traversal": {
        "Description": """Path traversal (also known as directory traversal) is a vulnerability that allows attackers to access files and directories stored outside the web root folder. By manipulating file path references using sequences like '../', attackers can break out of the intended directory structure.

This vulnerability typically occurs when user input is used to construct file paths without proper validation, allowing access to sensitive system files, application configuration, or other restricted resources.""",
        "CVSS": "7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)",
        "Impact": """1. Unauthorized access to sensitive files (passwords, configuration files, source code)
2. Exposure of system files (/etc/passwd, web server configs)
3. Access to application source code revealing business logic
4. Potential for privilege escalation
5. Information gathering for further attacks
6. In severe cases, ability to read private keys or credentials""",
        "Recommendation": """1. Validate and sanitize all user inputs used in file operations
2. Use whitelist approach for allowed files/paths
3. Implement proper access controls at the application level
4. Use built-in framework functions for file operations that handle path normalization
5. Run web server with minimal privileges
6. Disable dangerous functions in production (if using PHP: disable readfile, file_get_contents for user input)
7. Use chroot jails or containers to limit file system access
8. Regularly test for path traversal vulnerabilities"""
    },
    
    "SSL/TLS": {
        "Description": """SSL/TLS (Secure Sockets Layer/Transport Layer Security) provides encryption for data in transit between clients and servers. Weak SSL/TLS configurations, outdated protocols, weak ciphers, or certificate issues can expose communications to interception and manipulation.

Common issues include expired certificates, self-signed certificates in production, support for deprecated protocols (SSLv3, TLS 1.0, TLS 1.1), weak cipher suites, and missing security features like HSTS.""",
        "CVSS": "7.4 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N)",
        "Impact": """1. Man-in-the-middle attacks allowing traffic interception
2. Exposure of sensitive data transmitted over insecure connections
3. Session hijacking through unencrypted session tokens
4. Credential theft during authentication
5. Loss of user trust due to browser security warnings
6. Compliance violations (PCI-DSS, HIPAA, GDPR)
7. Vulnerability to known attacks (BEAST, POODLE, CRIME)""",
        "Recommendation": """1. Use valid certificates from trusted Certificate Authorities
2. Disable SSLv3, TLS 1.0, and TLS 1.1 - use TLS 1.2 or TLS 1.3
3. Configure strong cipher suites and disable weak ciphers
4. Implement HTTP Strict Transport Security (HSTS)
5. Enable Perfect Forward Secrecy (PFS)
6. Regularly monitor certificate expiration dates
7. Implement certificate pinning for mobile applications
8. Use tools like SSL Labs to test configuration
9. Keep OpenSSL/TLS libraries updated"""
    }
}


def enrich_finding_with_details(finding: dict) -> dict:
    """
    Enrich a finding dictionary with detailed information from the definitions database.
    
    Args:
        finding: A finding dict with at least 'Category' field
        
    Returns:
        Enriched finding dict with Description, CVSS, Impact, and Recommendation
    """
    category = finding.get("Category", "")
    
    # Try exact match first
    vuln_def = VULNERABILITY_DEFINITIONS.get(category)
    
    # If no exact match, try partial matching for common cases
    if not vuln_def:
        for def_category, details in VULNERABILITY_DEFINITIONS.items():
            if category.lower() in def_category.lower() or def_category.lower() in category.lower():
                vuln_def = details
                break
    
    # If still no match, provide generic information
    if not vuln_def:
        vuln_def = {
            "Description": finding.get("Description", "Security misconfiguration detected."),
            "CVSS": "N/A",
            "Impact": "This configuration may pose a security risk to the application.",
            "Recommendation": finding.get("Recommendation", "Review and remediate this security issue.")
        }
    
    # Create enriched finding
    enriched = finding.copy()
    
    # Add missing fields from definitions (don't override existing ones)
    if "Description" not in enriched or not enriched["Description"]:
        enriched["Description"] = vuln_def["Description"]
    
    if "CVSS" not in enriched or not enriched["CVSS"]:
        enriched["CVSS"] = vuln_def["CVSS"]
    
    # Special handling for HTTP Security Headers category
    if "HTTP Security Headers" in category or "Security Headers" in category:
        header_name = finding.get("Header", finding.get("Context", ""))
        
        # Check if we have specific header details
        if "HeaderDetails" in vuln_def and header_name in vuln_def["HeaderDetails"]:
            header_info = vuln_def["HeaderDetails"][header_name]
            enriched["Impact"] = header_info.get("Impact", vuln_def.get("Impact", ""))
            enriched["Recommendation"] = header_info.get("Recommendation", vuln_def.get("Recommendation", ""))
        else:
            # Use general category impact/recommendation if no specific header details
            if "Impact" not in enriched or not enriched["Impact"]:
                enriched["Impact"] = vuln_def.get("Impact", "")
            if "Recommendation" not in enriched or not enriched["Recommendation"]:
                enriched["Recommendation"] = vuln_def.get("Recommendation", "")
    else:
        # For non-header categories, use standard enrichment
        if "Impact" not in enriched or not enriched["Impact"]:
            enriched["Impact"] = vuln_def.get("Impact", "")
        
        if "Recommendation" not in enriched or not enriched["Recommendation"]:
            enriched["Recommendation"] = vuln_def.get("Recommendation", "")
    
    return enriched


def enrich_all_findings(findings: list) -> list:
    """
    Enrich all findings in a list with detailed vulnerability information.
    
    Args:
        findings: List of finding dicts
        
    Returns:
        List of enriched finding dicts
    """
    return [enrich_finding_with_details(f) for f in findings]