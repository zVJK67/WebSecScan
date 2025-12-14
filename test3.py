# vulnerability_definitions.py (test3.py)
"""
Vulnerability Definitions Database

Contains detailed information (Description, Impact, CVSS) for each vulnerability category.
This data enriches findings before report generation.
"""
COOKIE_SECURITY_DEF= {
    "DisplayName": "Improper Cookie and Session Security Configuration",

    "Description": (
        "Improper Cookie and Session Security Configuration occurs when cookies are set without essential "
        "security attributes or are scoped too broadly. Missing or weak cookie attributes such as HttpOnly, "
        "Secure, SameSite, and proper expiration increase the risk of session hijacking, cross-site scripting "
        "(XSS), cross-site request forgery (CSRF), and unauthorized access to user sessions."
    ),

    "DefaultSeverity": "High",
    "DefaultCVSS": "7.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N)",

    "TableType": None,
    "TableColumns": ["Scope", "Finding", "Evidence"],
    "TableColumnMap": {
        "Scope": ["Scope"],
        "Finding": ["Finding"],
        "Evidence": ["Evidence"]
    },

    "ItemDetails": {
        "HttpOnly": {
            "Impact": (
                "Allows client-side scripts to access session cookies, increasing the risk of session theft "
                "via Cross-Site Scripting (XSS) attacks."
            ),
            "Recommendation": (
                "Set the HttpOnly flag in all session cookies "
                "(e.g. Set-Cookie: sessionid=...; HttpOnly)."
            )
        },

        "Secure": {
            "Impact": (
                "Cookies may be transmitted over unencrypted HTTP connections, exposing session data to "
                "interception and man-in-the-middle (MITM) attacks."
            ),
            "Recommendation": (
                "Add the Secure flag to ensure cookies are only delivered via HTTPS "
                "(e.g. Set-Cookie: sessionid=...; Secure)."
            )
        },

        "SameSite": {
            "Impact": (
                "Increases exposure to Cross-Site Request Forgery (CSRF) attacks by allowing cookies to be "
                "sent with cross-site requests."
            ),
            "Recommendation": (
                "Set SameSite=Lax or SameSite=Strict for session cookies to mitigate CSRF attacks."
            )
        },

        "Path": {
            "Impact": (
                "Cookies are accessible across unnecessary application paths, increasing the attack surface "
                "and the impact of potential cookie compromise."
            ),
            "Recommendation": (
                "Restrict Path to required endpoints "
                "(e.g. Set-Cookie: sessionid=...; Path=/admin)."
            )
        },

        "Expires/Max-Age": {
            "Impact": (
                "Cookies may persist longer than intended, increasing the risk of session reuse and "
                "unauthorized access if a session is stolen."
            ),
            "Recommendation": (
                "Set a Max-Age or Expires attribute with an appropriate session lifetime."
            )
        },

        "Weak Session ID": {
            "Impact": (
                "Predictable or short session identifiers can be brute-forced or guessed, allowing attackers "
                "to hijack valid user sessions."
            ),
            "Recommendation": (
                "Use long, cryptographically secure random session identifiers (>=128 bits, "
                "e.g. sessionid=63b7c9f9f0a56edbcf9f1a31e9e1561c)."
            )
        },

        "Domain": {
            "Impact": (
                "Cookies scoped to overly broad domains can be accessed by unintended subdomains, increasing "
                "the risk of cross-subdomain session leakage."
            ),
            "Recommendation": (
                "Restrict the Domain attribute to the minimal required scope "
                "(e.g. auth.example.com)."
            )
        },

        "Excessive Lifetime": {
            "Impact": (
                "Long-lived cookies extend the window of opportunity for attackers to reuse stolen session "
                "tokens, increasing the likelihood of account compromise."
            ),
            "Recommendation": (
                "Limit long-term cookies to less than 1 year; session cookies should expire when the browser "
                "closes."
            )
        },

        "Overly Broad Path Attribute": {
            "Impact": (
                "Allows cookies to be sent to endpoints that do not require them, increasing the risk of "
                "unintended exposure and misuse."
            ),
            "Recommendation": (
                "Restrict Path to only required endpoints (e.g., Path=/admin)."
            )
        },

        "Overly Broad Domain Attribute": {
            "Impact": (
                "Cookies shared across multiple subdomains may be exposed to weaker or compromised "
                "applications within the same domain."
            ),
            "Recommendation": (
                "Restrict the Domain attribute to the specific subdomain that requires the cookie."
            )
        },

        "JavaScript-Only Cookie": {
            "Impact": (
                "Cookies set via JavaScript are vulnerable to XSS attacks and cannot be protected with "
                "HttpOnly, increasing the risk of session theft."
            ),
            "Recommendation": (
                "Avoid setting security-sensitive cookies using JavaScript. Use server-side Set-Cookie "
                "headers with proper attributes."
            )
        }
    }
}

VULNERABILITY_DEFINITIONS = {
    "HTTP Security Headers": {
        "DisplayName": "Misconfigured HTTP Security Header",
        
        "Description": """HTTP security headers provide yet another layer of security by helping to mitigate attacks and security vulnerabilities. Whenever a browser requests a page from a web server, the server responds with the content along with HTTP response headers. With the misconfigured or missing of HTTP security headers, the attackers may gain information from the data which may lead to various of attacks such as clickjacking, cross-site scripting (XSS) and others attacks as well.""",

        "DefaultSeverity": "Low",
        "DefaultCVSS": "3.1 (AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N)",

        "TableType": "headers",

        "ItemDetails": {
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
    
    "HTTP Methods": {
        "DisplayName": "Unsafe HTTP Methods Enabled",
        
        "Description": (
            "HTTP provides various methods to support development and debugging, but if misconfigured, some of these methods can expose serious security risks. Attackers may exploit them to "
            "upload or delete files, retrieve sensitive information, or abuse server functionality.\n\n"
            "The following methods should be disabled:\n"
            "- OPTIONS: This method is a diagnostic method which is mainly used for debugging purpose. "
            "It provides a list of the methods that are supported by the web server.\n"
            "- TRACE: This method simply echoes back to the client whatever string has been sent to the server, "
            "and is used mainly for debugging purposes.\n"
            "- PUT: This method allows a client to upload new files on the web server.\n"
            "- DELETE: This method allows a client to delete a file on the web server.\n"
            "- DEBUG: This method is used for debugging purposes. It allows developers to diagnose and troubleshoot issues by providing detailed information about the server's operation."
            ),

        "DefaultSeverity": "Medium",
        "DefaultCVSS": "5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)",
        "RiskRule": "methods_options_only",

        "TableType": "methods",

        # Only per-method IMPACT (no per-method recommendation)
        "ItemDetails": {
            "OPTIONS": {
                "Impact": "This method can be considered as a shortcut to find another hole."
            },
            "TRACE": {
                "Impact": "This method reflects the request back to the sender, which attackers can exploit to steal sensitive information via Cross-Site Tracing (XST)."
            },
            "PUT": {
                "Impact": "An attacker can exploit it by uploading malicious files, or by simply using the victim’s server as a file repository."
            },
            "DELETE": {
                "Impact": "An attacker can exploit it as a very simple and direct way to deface a web site or to mount a Denial of Service (DoS) attack."
            },
            "DEBUG": {
                "Impact": "An attacker can leverage this method to gain insights into the server's configuration, potentially exposing sensitive information and aiding in the exploitation of other vulnerabilities."
            }
        },

        "Recommendation": "Remove all unsafe HTTP methods."
    },
    
    
    "Server Info": {
        "DisplayName": "Server Information Disclosure",
        
        "Description": (
            "Server Information Disclosure occurs when a web server exposes details about its software, technologies, or behavior through HTTP headers or error responses. These "
            "details help attackers fingerprint the environment and identify version-specific vulnerabilities.\n\n"
            "Exposing server, technology, or framework details increases the chance attackers can find and use known exploits against specific versions. Error responses that reveal "
            "internal details further aid fingerprinting and targeted attacks."
        ),

        "DefaultSeverity": "Low",
        "DefaultCVSS": "3.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)",

        "TableType": None,
        "TableColumns": ["Finding", "Evidence"],    # visible column titles
        "TableColumnMap": {
            "Finding": ["Header", "_item_short", "Context"],
            "Evidence": ["CurrentValue", "Current Value", "Value", "Detail"]
        },

        "ItemDetails": {
            "Server Header Exposed": {
                "Impact": "Reveals server software and version (for example: gunicorn/19.9.0), which enables attackers to search for version-specific vulnerabilities and targeted exploits.",
                "Recommendation": "Disable or mask the Server header at the web server level (or via a reverse proxy) so it does not disclose product names or versions."
            },
            "Technology Header Exposed": {
                "Impact": "Discloses backend technology (for example: PHP/8.2), allowing attackers to focus on technology-specific attack vectors and known vulnerabilities.",
                "Recommendation": "Remove or obfuscate the X-Powered-By header in application or server configuration so implementation details are not disclosed."
            },
            "Framework/Generator Header Exposed": {
                "Impact": "Exposes framework or CMS versions (for example: WordPress, Laravel), helping attackers identify framework-specific exploits, vulnerable plugins, or misconfigurations.",
                "Recommendation": "Disable framework-identifying response headers in the application or CMS configuration and ensure plugins/modules do not leak version information."
            },
            "Error Pages Reveal Server Details": {
                "Impact": "Default/error pages or verbose error responses may reveal internal paths, server versions, stack traces, or other internal details that aid attacker fingerprinting and exploitation.",
                "Recommendation": "Replace default error pages with custom, generic error pages that do not disclose implementation details or stack traces. Log detailed errors server-side only."
            },
            "Server Behavioral Fingerprinting": {
                "Impact": "Distinctive response patterns (timing, header order, cookie formats) can allow attackers to infer the server type (e.g., Apache) or components even when headers are hidden, enabling tailored attacks.",
                "Recommendation": "Use a reverse proxy or WAF to normalize responses, unify headers, and reduce fingerprinting signals. Review and harden middleware behavior to avoid leaking identifiable patterns."
            }
        }
    },

    # Cookie Security (shared definition)
    "Cookie Security (Server-Side)": COOKIE_SECURITY_DEF,
    "Cookie Security (Client-Side)": COOKIE_SECURITY_DEF,
    
    "CORS Security": {
        "DisplayName": "Cross-Origin Resource Sharing (CORS) Misconfiguration",

        "Description": (
            "Cross-Origin Resource Sharing (CORS) controls how web applications allow cross-origin requests "
            "from different origins. Improper CORS configuration can allow unauthorized websites to read "
            "sensitive responses or perform authenticated actions on behalf of users.\n\n\n"
            "The scanner evaluates CORS behavior by comparing server responses under different request "
            "conditions, focusing on how CORS headers are handled when an Origin header is present or absent.\n\n "
            "- Access-Control-Allow-Origin (ACAO): The scanner checks whether the server responds with a wildcard (*)" 
            "or reflects arbitrary origins by sending requests with and without a malicious Origin (e.g., https://evil-attacker.com)."
            " This identifies overly permissive or origin-reflection issues.\n"
            "- Access-Control-Allow-Credentials (ACAC): The scanner verifies whether credentials are allowed in cross-origin requests and ensures "
            "that ACAC is not improperly combined with a wildcard origin, which would violate CORS security best practices.\n"
            "- Access-Control-Allow-Methods (ACAM): The scanner sends preflight OPTIONS requests to determine whether unnecessary or dangerous "
            "HTTP methods like PUT are exposed cross-origin.\n"
            "- Access-Control-Allow-Headers (ACAH): The scanner injects custom headers during preflight requests to observe whether the server allows"
            " arbitrary request headers, which could enable malicious cross-origin requests.\n"
            "- Access-Control-Max-Age (ACMA): The scanner checks whether preflight caching is enabled and evaluates if excessive caching could allow "
            "long-lived abuse of insecure CORS decisions.\n"
            "- Vary Header: The scanner inspects the Vary header to confirm whether responses are correctly varied based on Origin or preflight headers." 
            "Missing or incorrect Vary values may cause cache poisoning or unintended cross-origin data exposure.\n\n"
            "This multi-stage testing aligns with OWASP Origin Header Scrutiny recommendations."
        ),

        "DefaultSeverity": "High",
        "DefaultCVSS": "8.3 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N)",

        "TableType": None,
        "TableColumns": ["Finding", "Evidence"],
        "TableColumnMap": {
            "Finding": ["Type"],
            "Evidence": ["CurrentValue", "Detail"]
        },

        "ItemDetails": {
            "Wildcard Origin Allowed": {
                "Impact": (
                    "Allowing Access-Control-Allow-Origin: * permits any external website to read cross-origin "
                    "responses. This significantly increases the attack surface and may allow attackers to "
                    "access sensitive API responses or application data from untrusted origins."
                ),
                "Recommendation": (
                    "Specify only trusted, legitimate domains instead of using a wildcard (*)."
                )
            },

            "Credentials Allowed for All Origins": {
                "Impact": (
                    "Combining Access-Control-Allow-Credentials: true with a permissive origin policy enables "
                    "attackers to perform authenticated cross-origin requests. This can lead to unauthorized "
                    "access to user data, session hijacking, or account compromise."
                ),
                "Recommendation": (
                    "Only enable credentials for specific trusted domains. Ensure "
                    "Access-Control-Allow-Credentials: true is never used with Access-Control-Allow-Origin: *."
                )
            },

            "Unsafe Origin Reflection": {
                "Impact": (
                    "Reflecting arbitrary Origin values effectively trusts all requesting domains. This allows "
                    "malicious websites to bypass same-origin protections and read sensitive responses, enabling "
                    "data theft and abuse of authenticated user sessions."
                ),
                "Recommendation": (
                    "Replace dynamic origin reflection with a fixed whitelist of allowed origins. Reject "
                    "unexpected or untrusted origins."
                )
            },

            "Excessive Allowed Methods": {
                "Impact": (
                    "Allowing unnecessary HTTP methods increases the attack surface by exposing endpoints to "
                    "methods that may not be securely implemented. Attackers can exploit unused or unsafe "
                    "methods to manipulate server resources or bypass access controls."
                ),
                "Recommendation": (
                    "Restrict allowed methods to only those required by the application (e.g., GET, POST)."
                )
            },

            "Missing Vary Origin Header": {
                "Impact": (
                    "Without Vary: Origin, shared caches may serve CORS responses intended for one origin to "
                    "another. This can result in unauthorized data exposure due to incorrect caching behavior."
                ),
                "Recommendation": (
                    "Add Vary: Origin when the server returns different CORS responses based on the request Origin."
                )
            },

            "Unsafe Vary Origin Usage": {
                "Impact": (
                    "When unsafe CORS policies are combined with Vary: Origin, insecure responses may be cached "
                    "and reused. This amplifies the impact of misconfiguration by persistently serving permissive "
                    "CORS responses to untrusted origins."
                ),
                "Recommendation": (
                    "Fix the CORS policy first (proper whitelist, no wildcard with credentials). Only rely on "
                    "Vary: Origin after the policy is secure."
                )
            },

            "Missing Access-Control-Max-Age": {
                "Impact": (
                    "The absence of Access-Control-Max-Age causes browsers to repeatedly perform preflight "
                    "requests. While not directly exploitable, this can degrade performance and increase server "
                    "load."
                ),
                "Recommendation": (
                    "Set a reasonable Access-Control-Max-Age value (e.g., 300–600 seconds)."
                )
            },

            "Excessive Access-Control-Max-Age": {
                "Impact": (
                    "Excessively long CORS caching allows outdated or incorrect permissions to persist in "
                    "browsers, prolonging exposure to unauthorized cross-origin access."
                ),
                "Recommendation": (
                    "Avoid extremely long caching durations; use moderate values such as 300–600 seconds."
                )
            },

            "CORS Enabled on Unnecessary Endpoints": {
                "Impact": (
                    "Enabling CORS on endpoints that do not require cross-origin access increases the risk of "
                    "data leakage, CSRF-like abuse, and unauthorized interaction from external domains."
                ),
                "Recommendation": (
                    "Only enable CORS for specific API endpoints that truly require cross-origin requests. "
                    "Disable it for sensitive or internal routes."
                )
            },

            "Preflight Accepts Untrusted Origins": {
                "Impact": (
                    "Accepting preflight requests from untrusted origins grants attackers visibility into "
                    "allowed methods and permissions, enabling malicious domains to perform fully authorized "
                    "cross-origin requests."
                ),
                "Recommendation": (
                    "Update preflight validation to reject unapproved origins before responding with CORS "
                    "permissions."
                )
            }
        }
    },
    
    "Directory Exposure": {
        "DisplayName": "Sensitive Directory and File Exposure",

        "Description": (
            "Directory exposure occurs when web servers are misconfigured to display directory listings or when "
            "sensitive files and directories are accessible without proper authentication. This can reveal the "
            "application's file structure, backup files, configuration files, and other sensitive information."
        ),

        "DefaultSeverity": "Medium",
        "DefaultCVSS": "5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)",

        "TableType": None,
        "TableColumns": ["Finding", "Status", "URL"],
        "TableColumnMap": {
            "Finding": ["RelPath"],
            "Status": ["Status"],
            "URL": ["URL"]
        },

        "ItemDetails": {
            ".env": {
                "Impact": "Environment variables and application secrets may be exposed, leading to credential leakage or system compromise."
            },
            "config": {
                "Impact": "Configuration files may reveal sensitive settings such as database credentials or API keys."
            },
            "backup": {
                "Impact": "Backup files may contain sensitive data, credentials, or full source code copies."
            },
            ".git": {
                "Impact": "Exposed Git repository data can reveal source code, commit history, and sensitive information."
            },
            "phpinfo": {
                "Impact": "PHP configuration disclosure reveals server details, installed modules, and environment settings."
            },
            ".htaccess": {
                "Impact": "Apache configuration files may reveal security rules, access controls, or internal paths."
            },
            ".htpasswd": {
                "Impact": "Password files may expose authentication credentials or hashed passwords."
            },
            "admin": {
                "Impact": "Administrative interfaces accessible to unauthenticated users may allow unauthorized control."
            },
            ".DS_Store": {
                "Impact": "macOS metadata files may reveal directory structure and internal file names."
            },
            "logs": {
                "Impact": "Log files may contain sensitive information such as credentials, tokens, or system paths."
            },
            "error_log": {
                "Impact": "Error logs may reveal internal system paths, stack traces, or exploitable vulnerabilities."
            },
            "readme": {
                "Impact": "Documentation files may reveal software versions, configurations, or deployment details."
            },
            "sitemap": {
                "Impact": "Site structure disclosure aids reconnaissance and helps attackers identify sensitive endpoints."
            },
            "robots.txt": {
                "Impact": "Robots.txt may reveal paths that are hidden from crawlers but still accessible to attackers."
            }
        },

        "Recommendation": (
            "- Remove sensitive files and folders from the webroot\n"
            "- Deny HTTP access to hidden or sensitive files at the server layer\n"
            "- Disable directory listing\n"
            "- Use strict file and folder permissions\n"
            "- Review for exposed secrets and rotate them if necessary"
        )
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

def _normalize_item_key(s: str) -> str:
    """
    Normalize finding item names so they match ItemDetails keys.
    Removes parentheses and extra suffixes.
    """
    if not s:
        return ""
    s = str(s).strip()
    # remove text in parentheses
    if "(" in s:
        s = s.split("(", 1)[0].strip()
    return s

def enrich_finding_with_details(finding: dict) -> dict:
    """
    Enrich a finding dictionary with detailed information from the definitions database.

    - Safely reads CVSS (supports either 'CVSS' or 'DefaultCVSS' in definitions).
    - Supports per-item detail blocks named 'ItemDetails', 'HeaderDetails' or 'MethodDetails'.
    - Does not overwrite fields that are already present in the finding.
    """
    category = finding.get("Category", "") or ""

    # try exact match first
    vuln_def = VULNERABILITY_DEFINITIONS.get(category)

    # if no exact match, try best-effort substring matching
    if not vuln_def:
        for def_category, details in VULNERABILITY_DEFINITIONS.items():
            if category and (category.lower() in def_category.lower() or def_category.lower() in category.lower()):
                vuln_def = details
                break

    # fallback to a minimal definition if nothing found
    if not vuln_def:
        vuln_def = {
            "Description": finding.get("Description", "Security misconfiguration detected."),
            "CVSS": finding.get("CVSS") or "N/A",
            "Impact": "This configuration may pose a security risk to the application.",
            "Recommendation": finding.get("Recommendation", "Review and remediate this security issue.")
        }

    # start with a shallow copy so we don't mutate original input
    enriched = finding.copy()

    # Description: prefer finding value, otherwise use vuln_def Description (if present)
    if not enriched.get("Description"):
        enriched["Description"] = vuln_def.get("Description", "")

    # CVSS: check multiple possible keys in the definitions, then fall back to any finding value, then 'N/A'
    enriched_cvss = enriched.get("CVSS") or vuln_def.get("CVSS") or vuln_def.get("DefaultCVSS") or "N/A"
    enriched["CVSS"] = enriched_cvss

    # Determine which per-item details map to use (support multiple legacy names)
    per_item_keys = []
    for key_name in ("ItemDetails", "HeaderDetails", "MethodDetails"):
        if isinstance(vuln_def.get(key_name), dict):
            per_item_keys.append(key_name)

    # Normalize item identifier for lookup (e.g., "HTTP Method: OPTIONS" -> "OPTIONS")
    item_name = (
        finding.get("_item_short")
        or finding.get("Header")
        or finding.get("Method")
        or finding.get("Context")
        or finding.get("Detail")
        or finding.get("name")
        or ""
    )
    short_name = ""
    if item_name:
        try:
            s = str(item_name).strip()
            if ":" in s:
                s = s.split(":", 1)[1].strip()
            short_name = s
        except Exception:
            short_name = str(item_name)

    # If we have per-item detail maps, try to attach Impact/Recommendation for the item
    attached = False
    for key_name in per_item_keys:
        item_map = vuln_def.get(key_name, {}) or {}
        # prefer short_name lookup, fallback to raw item_name
        raw_key = short_name if short_name else item_name
        norm_key = _normalize_item_key(raw_key)

        candidates = [
            norm_key,
            norm_key.upper(),
            norm_key.lower(),
        ]

        item_def = {}
        for k in candidates:
            if k in item_map:
                item_def = item_map[k] or {}
                break

        if item_def:
            # Impact
            if item_def.get("Impact") and not enriched.get("Impact"):
                enriched["Impact"] = item_def.get("Impact")
            # Recommendation
            if item_def.get("Recommendation") and not enriched.get("Recommendation"):
                enriched["Recommendation"] = item_def.get("Recommendation")
            attached = True
            break

    # If nothing attached above, fall back to category-level Impact/Recommendation if finding lacks them
    if not attached:
        if not enriched.get("Impact"):
            enriched["Impact"] = vuln_def.get("Impact", "")
        if not enriched.get("Recommendation"):
            # support both 'Recommendation' and 'Recommendations' variants (just in case)
            enriched["Recommendation"] = vuln_def.get("Recommendation") or vuln_def.get("Recommendations") or ""

    return enriched


def enrich_all_findings(findings: list) -> list:
    """
    Enrich all findings in a list with detailed vulnerability information.
    Returns list of enriched finding dicts.
    """
    if not findings:
        return []
    enriched_list = []
    for f in findings:
        try:
            enriched_list.append(enrich_finding_with_details(f))
        except Exception:
            # defensive: if a particular finding enrichment fails, include original but don't crash
            import traceback
            traceback.print_exc()
            enriched_list.append(f)
    return enriched_list
