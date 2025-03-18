import random
import uuid
from datetime import datetime, timedelta
import ipaddress
from typing import Dict, Any, List

# Attack types, severities, and statuses
ATTACK_TYPES = [
    "SQL Injection", 
    "Cross-Site Scripting (XSS)", 
    "Brute Force", 
    "DDoS", 
    "Directory Traversal", 
    "Command Injection",
    "File Upload Exploit",
    "CSRF Attack",
    "Server-Side Request Forgery",
    "XML External Entity Attack"
]

SEVERITIES = ["Low", "Medium", "High"]
STATUSES = ["Active", "Mitigated"]

# Common user agents for simulation
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0"
]

# Common HTTP methods
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"]

# Common URL paths for attacks
URL_PATHS = [
    "/login", 
    "/admin", 
    "/upload", 
    "/profile", 
    "/api/users",
    "/search",
    "/reset-password",
    "/checkout",
    "/report",
    "/download"
]

def generate_random_ip() -> str:
    """Generate a random IP address"""
    # Avoid reserved and private IP ranges for more realistic "external" IPs
    while True:
        ip = str(ipaddress.IPv4Address(random.randint(1, 2**32-1)))
        
        # Skip private ranges
        if not (ip.startswith('10.') or 
                ip.startswith('172.16.') or 
                ip.startswith('192.168.')):
            return ip

def generate_random_timestamp(days_back: int = 30) -> str:
    """Generate a random timestamp within the last n days"""
    now = datetime.now()
    random_date = now - timedelta(
        days=random.randint(0, days_back),
        hours=random.randint(0, 23),
        minutes=random.randint(0, 59),
        seconds=random.randint(0, 59)
    )
    return random_date.isoformat()

def generate_attack_details(attack_type: str) -> Dict[str, Any]:
    """Generate attack-specific details based on attack type"""
    details = {
        "user_agent": random.choice(USER_AGENTS),
        "method": random.choice(HTTP_METHODS),
        "url_path": random.choice(URL_PATHS),
        "source_port": random.randint(10000, 65535),
        "destination_port": random.choice([80, 443, 8080, 8443, 3000, 5000])
    }
    
    # Add attack-specific details
    if attack_type == "SQL Injection":
        details["payload"] = random.choice([
            "' OR 1=1 --", 
            "admin' --", 
            "'; DROP TABLE users; --",
            "' UNION SELECT username,password FROM users --"
        ])
    elif attack_type == "Cross-Site Scripting (XSS)":
        details["payload"] = random.choice([
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')"
        ])
    elif attack_type == "Brute Force":
        details["failed_attempts"] = random.randint(5, 50)
        details["target_account"] = random.choice(["admin", "root", "user", "support", "webmaster"])
    elif attack_type == "DDoS":
        details["request_rate"] = f"{random.randint(1000, 10000)} requests/second"
        details["traffic_volume"] = f"{random.randint(10, 100)} GB/s"
        details["botnet_size"] = random.randint(100, 10000)
    
    return details

def generate_fake_attack() -> Dict[str, Any]:
    """Generate a complete fake attack log"""
    attack_type = random.choice(ATTACK_TYPES)
    severity = random.choice(SEVERITIES)
    
    # Higher severity attacks are more likely to be active
    if severity == "High":
        status = random.choices(STATUSES, weights=[0.7, 0.3], k=1)[0]
    elif severity == "Medium":
        status = random.choices(STATUSES, weights=[0.5, 0.5], k=1)[0]
    else:
        status = random.choices(STATUSES, weights=[0.3, 0.7], k=1)[0]
    
    return {
        "id": str(uuid.uuid4()),
        "timestamp": generate_random_timestamp(),
        "ip": generate_random_ip(),
        "attack_type": attack_type,
        "severity": severity,
        "status": status,
        "details": generate_attack_details(attack_type)
    }

def generate_batch(count: int = 10) -> List[Dict[str, Any]]:
    """Generate a batch of fake attack logs"""
    return [generate_fake_attack() for _ in range(count)]