#this file is used to extract and detect sensitive information from the input content. 
#It uses regex patterns to identify potential risks and generates insights based on the findings. 
#The results are then used to calculate a risk score and determine the appropriate action.

import re

def parse_and_detect(content: str) -> list:
    """
    Scans text/log content line-by-line using Regex to detect sensitive data
    and security issues.
    """
    findings = []
    lines = content.split('\n')

    # 1. Define Regex Patterns -> Passwords, API KEYS, LEAKS,EMAIL
    patterns = {
        "email": re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'),
        
        "api_key": re.compile(r'(?i)(?:api_key|apikey|token|secret)[\s:=]+([a-zA-Z0-9_\-]{10,}|sk-[a-zA-Z0-9\-]+)'), 
        
        "password": re.compile(r'(?i)(?:password|pwd|pass)[\s:=]+([^\s,]+)'),
        
        "error_leak": re.compile(r'(?i)(error|exception|stack trace|at\s+[a-zA-Z0-9_.]+\.[a-zA-Z0-9_]+\([a-zA-Z0-9_.]+\:\d+\))')
    }

    #Assigning risk levels to each type of finding for later use in the risk engine
    risk_mapping = {
        "email": "low",
        "api_key": "high",
        "password": "critical",
        "error_leak": "medium"
    }

    #Line-by-Line Scanning
    for i, line in enumerate(lines):
        line_num = i + 1 
        
        # Extract Emails
        for match in patterns["email"].finditer(line):
            findings.append({
                "type": "email", 
                "risk": risk_mapping["email"], 
                "line": line_num, 
                "value": match.group(0)
            })
        
        # Extract API Keys
        for match in patterns["api_key"].finditer(line):
            val = match.group(1) if match.lastindex else match.group(0)
            findings.append({
                "type": "api_key", 
                "risk": risk_mapping["api_key"], 
                "line": line_num, 
                "value": val
            })
            
        # Extract Passwords
        for match in patterns["password"].finditer(line):
            val = match.group(1) if match.lastindex else match.group(0)
            findings.append({
                "type": "password", 
                "risk": risk_mapping["password"], 
                "line": line_num, 
                "value": val
            })

        # Detect Stack Traces & Errors
        if patterns["error_leak"].search(line):
            findings.append({
                "type": "stack_trace", 
                "risk": risk_mapping["error_leak"], 
                "line": line_num, 
                "value": "System error or stack trace detected"
            })

    return findings

#Sample test....
if __name__ == "__main__":
    sample_log = "2026-03-10 10:00:01 INFO User login    email=admin@company.com    password=admin123    api_key=sk-prod-xyz    ERROR stack trace: NullPointerException at service.java:45"
    
    results = parse_and_detect(sample_log)
    for r in results:
        print(r)