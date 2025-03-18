import random
from typing import Dict, Any
import re

# Define attack types with associated severity distributions and recommendations
ATTACK_TYPES = {
    "SQL Injection": {
        "severities": {"Low": 0.2, "Medium": 0.5, "High": 0.3},
        "recommendation": "Implement input validation and prepared statements"
    },
    "Cross-Site Scripting (XSS)": {
        "severities": {"Low": 0.3, "Medium": 0.5, "High": 0.2},
        "recommendation": "Implement content security policy and input sanitization"
    },
    "Brute Force": {
        "severities": {"Low": 0.4, "Medium": 0.4, "High": 0.2},
        "recommendation": "Implement account lockout and rate limiting"
    },
    "DDoS": {
        "severities": {"Low": 0.1, "Medium": 0.3, "High": 0.6},
        "recommendation": "Implement rate limiting and traffic analysis"
    },
    "Directory Traversal": {
        "severities": {"Low": 0.2, "Medium": 0.6, "High": 0.2},
        "recommendation": "Validate file paths and implement proper access controls"
    },
    "Command Injection": {
        "severities": {"Low": 0.1, "Medium": 0.3, "High": 0.6},
        "recommendation": "Use safer APIs and implement input validation"
    },
    "File Upload Exploit": {
        "severities": {"Low": 0.2, "Medium": 0.5, "High": 0.3},
        "recommendation": "Validate file types, extensions, and implement virus scanning"
    },
    "CSRF Attack": {
        "severities": {"Low": 0.3, "Medium": 0.5, "High": 0.2},
        "recommendation": "Implement anti-CSRF tokens and SameSite cookie attributes"
    },
    "Server-Side Request Forgery": {
        "severities": {"Low": 0.2, "Medium": 0.4, "High": 0.4},
        "recommendation": "Implement strict URL validation and allowlists"
    },
    "XML External Entity Attack": {
        "severities": {"Low": 0.1, "Medium": 0.3, "High": 0.6},
        "recommendation": "Disable XML external entity processing and validate XML input"
    },
    "JWT Token Tampering": {
        "severities": {"Low": 0.2, "Medium": 0.4, "High": 0.4},
        "recommendation": "Use strong signature algorithms and validate all JWT claims"
    },
    "Path Traversal": {
        "severities": {"Low": 0.2, "Medium": 0.5, "High": 0.3},
        "recommendation": "Validate and sanitize file paths, use secure file handling APIs"
    },
    "Server Misconfiguration": {
        "severities": {"Low": 0.3, "Medium": 0.5, "High": 0.2},
        "recommendation": "Implement security headers and follow hardening guidelines"
    },
    "Insecure Deserialization": {
        "severities": {"Low": 0.1, "Medium": 0.3, "High": 0.6},
        "recommendation": "Implement integrity checks and avoid unsafe deserialization libraries"
    },
    "API Key Exposure": {
        "severities": {"Low": 0.2, "Medium": 0.5, "High": 0.3},
        "recommendation": "Use secure storage for API keys and implement proper authentication"
    },
    "OAuth Misconfiguration": {
        "severities": {"Low": 0.2, "Medium": 0.6, "High": 0.2},
        "recommendation": "Implement proper OAuth flow and validate redirect URIs"
    },
    "Log Injection": {
        "severities": {"Low": 0.4, "Medium": 0.4, "High": 0.2},
        "recommendation": "Sanitize log data and implement log monitoring"
    },
    "Zero-Day Exploit": {
        "severities": {"Low": 0.0, "Medium": 0.2, "High": 0.8},
        "recommendation": "Apply emergency patches and implement defense-in-depth strategies"
    },
    "Supply Chain Attack": {
        "severities": {"Low": 0.1, "Medium": 0.3, "High": 0.6},
        "recommendation": "Verify dependency integrity and implement software bill of materials"
    },
    "Session Fixation": {
        "severities": {"Low": 0.2, "Medium": 0.5, "High": 0.3},
        "recommendation": "Regenerate session IDs after authentication and validate session tokens"
    },
    "Man-in-the-Middle": {
        "severities": {"Low": 0.1, "Medium": 0.4, "High": 0.5},
        "recommendation": "Implement proper TLS/SSL configuration and certificate pinning"
    },
    "Credential Stuffing": {
        "severities": {"Low": 0.3, "Medium": 0.5, "High": 0.2},
        "recommendation": "Implement MFA and monitor for unusual login patterns"
    }
}

# Attack patterns for simple heuristic detection
ATTACK_PATTERNS = {
    "SQL Injection": ["SELECT", "DROP", "1=1", "OR 1=1", "--", ";--", "' OR '", "UNION", "INSERT INTO", "UPDATE SET"],
    "Cross-Site Scripting (XSS)": ["<script>", "alert(", "javascript:", "onerror=", "onload=", "eval(", "document.cookie", "fromCharCode"],
    "Directory Traversal": ["../", "..\\", "/etc/passwd", "../../", "c:\\windows", "boot.ini", ".htaccess"],
    "Command Injection": [";", "&&", "||", "`", "$(",  "system(", "exec(", "ping -c", "rm -rf", ">output.txt"],
    "File Upload Exploit": [".php", ".jsp", ".asp", ".exe", ".bat", "Content-Type: application/x-php", ".phar", ".cgi"],
    "CSRF Attack": ["X-CSRF-Token: null", "SameSite=None", "X-CSRF-Token missing", "cross-site request"],
    "Server-Side Request Forgery": ["localhost", "127.0.0.1", "0.0.0.0", "169.254", "file:///", "http://internal-service"],
    "XML External Entity Attack": ["<!ENTITY", "<!DOCTYPE", "SYSTEM", "file:///", "PUBLIC", "DTD"],
    "JWT Token Tampering": ["alg:none", "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0", "..", "algorithm=none"],
    "Path Traversal": ["../../../", "..%2f..%2f", "file:///etc/", "c:\\windows\\system32\\"],
    "Server Misconfiguration": ["X-Powered-By", "Server: Apache", "X-AspNet-Version", "TRACE method enabled"],
    "Insecure Deserialization": ["O:8:", "rO0", "__PHP_Incomplete_Class", "ObjectInputStream", "readObject"],
    "API Key Exposure": ["api_key=", "apikey=", "api-key:", "x-api-key:", "key=sk_"],
    "OAuth Misconfiguration": ["redirect_uri=", "client_secret=", "response_type=token", "state="],
    "Log Injection": ["\n\r", "%0d%0a", "User-Agent: null", "log poisoning"],
    "Zero-Day Exploit": ["CVE-", "exploit new vulnerability", "unpatched", "0-day"],
    "Supply Chain Attack": ["compromise package", "modified dependency", "trojan package", "compromised registry"],
    "Session Fixation": ["JSESSIONID=", "PHPSESSID=", "session transfer", "set-cookie"],
    "Man-in-the-Middle": ["certificate error", "untrusted CA", "SSL strip", "ARP spoofing"],
    "Credential Stuffing": ["multiple login attempts", "password=123456", "username admin password admin"]
}

# Enhanced pattern matching with more sophisticated regexes
ADVANCED_PATTERNS = {
    "SQL Injection": [
        re.compile(r"(?i)'.*?(?:--|;|/\*|or|and|union)"),
        re.compile(r"(?i)(?:union\s+all\s+select)"),
        re.compile(r"(?i)(?:select\s+(?:.*?)\s+from)")
    ],
    "Cross-Site Scripting (XSS)": [
        re.compile(r"(?i)<[^>]*?script[^>]*?>"),
        re.compile(r"(?i)on(?:error|load|click|mouseover)="),
        re.compile(r"(?i)(?:javascript|data):.*?")
    ],
    "Path Traversal": [
        re.compile(r"(?i)(?:\.\./|\.\\.\\|\.\.%2f|%252e%252e)"),
        re.compile(r"(?i)(?:/etc/passwd|/windows/win.ini|c:\\boot\.ini)")
    ],
    "Command Injection": [
        re.compile(r"(?i)(?:;|\||&&|\$\(|\`)\s*(?:cat|ls|dir|rm|wget|curl)"),
        re.compile(r"(?i)(?:system|exec|shell_exec|passthru)\s*\(")
    ]
}

# Behavioral patterns - sequences of actions that suggest attacks
BEHAVIOR_PATTERNS = {
    "Brute Force": {
        "conditions": [
            lambda data: data.get("failed_attempts", 0) > 3,
            lambda data: "password" in str(data).lower(),
            lambda data: data.get("request_interval", 1000) < 200  # ms between attempts
        ]
    },
    "DDoS": {
        "conditions": [
            lambda data: data.get("requests_per_minute", 0) > 100,
            lambda data: data.get("unique_ips", 1) > 5,
            lambda data: data.get("bandwidth", 0) > 1000000  # bytes/sec
        ]
    },
    "Credential Stuffing": {
        "conditions": [
            lambda data: data.get("unique_usernames", 0) > 5,
            lambda data: data.get("login_attempts", 0) > 10, 
            lambda data: data.get("success_ratio", 0.5) < 0.2
        ]
    }
}

def predict_attack(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Simulate AI model prediction for attack detection
    Using pattern matching with randomization for simulation
    """
    # Default response with no attack
    result = {
        "attack_detected": False,
        "attack_type": None,
        "severity": None,
        "confidence_score": random.uniform(20, 40),  # Lower confidence for non-attacks
        "recommendation": None
    }
    
    # Convert the entire data structure to a string for pattern matching
    data_string = str(data).lower()
    
    # Pattern-based detection
    detected_attacks = []
    detection_scores = {}
    
    # Basic pattern matching
    for attack_type, patterns in ATTACK_PATTERNS.items():
        matches = 0
        for pattern in patterns:
            if pattern.lower() in data_string:
                matches += 1
        
        if matches > 0:
            score = min(95, (matches / len(patterns)) * 100)
            detected_attacks.append(attack_type)
            detection_scores[attack_type] = score
    
    # Advanced regex pattern matching
    for attack_type, patterns in ADVANCED_PATTERNS.items():
        if attack_type not in detected_attacks:
            matches = 0
            for pattern in patterns:
                if pattern.search(data_string):
                    matches += 1
            
            if matches > 0:
                score = min(98, (matches / len(patterns)) * 100)
                detected_attacks.append(attack_type)
                detection_scores[attack_type] = score
    
    # Behavioral pattern detection
    for attack_type, behavior in BEHAVIOR_PATTERNS.items():
        matching_conditions = sum(1 for condition in behavior["conditions"] if condition(data))
        if matching_conditions / len(behavior["conditions"]) >= 0.5:  # At least half of conditions match
            score = (matching_conditions / len(behavior["conditions"])) * 100
            detected_attacks.append(attack_type)
            detection_scores[attack_type] = score
    
    # Random chance to detect attack even if no patterns match (false positive simulation)
    if not detected_attacks and random.random() < 0.15:  # 15% chance of false positive
        attack_type = random.choice(list(ATTACK_TYPES.keys()))
        detected_attacks.append(attack_type)
        detection_scores[attack_type] = random.uniform(60, 75)  # Lower confidence for false positives
    
    # Random chance to miss attack even if patterns match (false negative simulation)
    if detected_attacks and random.random() < 0.1:  # 10% chance of false negative
        return result
    
    # If we have detected attacks, select one (or random if multiple)
    if detected_attacks:
        # Select attack with highest detection score, or random if tied
        top_score = 0
        top_attacks = []
        for attack in detected_attacks:
            score = detection_scores.get(attack, 0)
            if score > top_score:
                top_score = score
                top_attacks = [attack]
            elif score == top_score:
                top_attacks.append(attack)
        
        attack_type = random.choice(top_attacks)
        
        # Get severity distribution for this attack type
        severity_dist = ATTACK_TYPES[attack_type]["severities"]
        severity = random.choices(
            list(severity_dist.keys()), 
            weights=list(severity_dist.values()),
            k=1
        )[0]
        
        # Set confidence score based on detection score and severity
        base_confidence = detection_scores.get(attack_type, random.uniform(60, 90))
        severity_boost = {"Low": 0, "Medium": 5, "High": 10}[severity]
        confidence_score = min(99.9, base_confidence + severity_boost)
        
        # Update result with attack information
        result.update({
            "attack_detected": True,
            "attack_type": attack_type,
            "severity": severity,
            "confidence_score": round(confidence_score, 1),
            "recommendation": ATTACK_TYPES[attack_type]["recommendation"]
        })
    
    return result