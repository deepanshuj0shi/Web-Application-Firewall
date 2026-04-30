# Web-Application-Firewall
Flask-Based Security Dashboard

This project presents a practical implementation of a Web Application Firewall (WAF) designed to monitor, analyze, and detect malicious web requests in real time. The system is built using Flask and focuses on identifying common web vulnerabilities such as SQL Injection and Cross-Site Scripting (XSS) through pattern-based detection.

Unlike production-grade WAFs, this project is intentionally simplified to help understand how request filtering, attack detection, and logging actually work at a fundamental level.

Project Vision

The goal of this project is not to build another “tool”, but to understand the thinking behind web security systems.

Most students know what SQL Injection or XSS is, but very few understand how systems actually detect them in real-time. This project bridges that gap.

It demonstrates:

How incoming HTTP requests are intercepted
How payloads are analyzed before reaching the application
How attack signatures can be identified using regex
How basic logging helps in forensic analysis
Core Functionality

The system operates as a middleware layer inside a Flask application, inspecting every incoming request before it reaches the main route.

1. Request Interception and Monitoring

Every request is captured using Flask’s before_request hook. At this stage, the system extracts:

Source IP address
HTTP method (GET/POST)
URL path
Query parameters
Form data
JSON payload

This gives complete visibility into what the client is sending.

2. Attack Detection Engine

The core detection logic is based on predefined regex signatures.

The system checks the payload against patterns such as:

SQL Injection:
Tautology attacks (OR 1=1)
UNION-based extraction
Piggyback queries (; DROP TABLE)
Encoding bypass techniques (Hex / CHAR)
Cross-Site Scripting (XSS):
Script tag injection
Event handlers (onerror, onclick)
JavaScript protocol injection
HTML entity encoding
iframe injection

If any pattern matches, the request is flagged as malicious.

3. Real-Time Response Handling

Once an attack is detected:

The request is not processed normally
The system marks it as malicious
The UI displays:
 Attack Detected + Attack Type

If no threat is found:

The request is treated as safe
The UI displays:
Safe Input
4. Forensic Logging

Every request is logged in detail in the terminal.

This includes:

Timestamp
IP address
Request method
Payload data

This simulates how real security systems maintain logs for investigation and auditing.

System Workflow

-User submits input from the dashboard

-Request is intercepted before reaching route

-Payload is extracted and analyzed

-Regex engine checks for attack signatures

-Result is returned to UI (Safe / Attack)

-Request details are logged

-Technology Stack

-Backend

-Python (Flask framework)

-Frontend

-HTML + Bootstrap (for clean UI)

-Security Logic

-Python Regex (re module)

#Project Structure

waf-project/
│── app.py                 # Main Flask app with WAF logic
│── templates/
│     └── index.html       # Dashboard UI
│── README.md

#How to Run

Install dependencies

-pip install flask

-Run the application

-python app.py

-Open in browser

-http://127.0.0.1:5000

-Testing the System

You can test the detection engine using sample payloads.


#SQL Injection
' OR '1'='1
UNION SELECT username, password FROM users

#XSS
<script>alert('XSS')</script>
<img src=x onerror=alert(1)>

#Limitations

-Regex-based detection can be bypassed easily
-No protection against advanced payload obfuscation
-No rate limiting or IP blocking
-No integration with real-world traffic

This is a learning model

#Future Improvements

-Add anomaly-based detection (ML-based)

-Store logs in a database

-Implement IP blocking / rate limiting

-Build an analytics dashboard
