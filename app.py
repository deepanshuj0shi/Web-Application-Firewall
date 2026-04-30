# ------------------------------------------
# IMPORTS
# ------------------------------------------
from flask import Flask, request, render_template, g
import datetime
import re
import os


# ------------------------------------------
# FLASK APPLICATION
# ------------------------------------------
app = Flask(__name__)


# ------------------------------------------
# REGEX SIGNATURE DATABASE
# ------------------------------------------

REGEX_RULES = {

    # SQL Injection: Tautology attacks
    "SQLi Tautology": re.compile(
        r"(\bOR\b|\bAND\b).*(=|LIKE)",
        re.IGNORECASE
    ),

    # SQL Injection: UNION-based attacks
    "SQLi UNION Attack": re.compile(
        r"\bUNION\b\s+\bSELECT\b",
        re.IGNORECASE
    ),

    # SQL Injection: Piggyback queries
    "SQLi Piggyback Query": re.compile(
        r";\s*(DROP|INSERT|DELETE|UPDATE|ALTER|CREATE)\s+",
        re.IGNORECASE
    ),

    # SQL Injection: Hex Encoding
    "SQLi Hex Encoding": re.compile(
        r"0x[0-9a-fA-F]+",
        re.IGNORECASE
    ),

    # SQL Injection: CHAR Encoding
    "SQLi Char Encoding": re.compile(
        r"\bCHAR\s*\(\s*\d+\s*\)",
        re.IGNORECASE
    ),

    # XSS: Script Tag Injection
    "XSS Script Tag": re.compile(
        r"<\s*script.*?>",
        re.IGNORECASE
    ),

    # XSS: Event Handler Injection
    "XSS Event Handler": re.compile(
        r"on(load|error|click|mouseover|focus)\s*=",
        re.IGNORECASE
    ),

    # XSS: JavaScript Protocol
    "XSS JavaScript Protocol": re.compile(
        r"javascript\s*:",
        re.IGNORECASE
    ),

    # XSS: HTML Entity Encoding
    "XSS HTML Entity": re.compile(
        r"&#x?[0-9a-fA-F]+;",
        re.IGNORECASE
    ),

    # XSS: iframe Injection
    "XSS Iframe Injection": re.compile(
        r"<\s*iframe.*?>",
        re.IGNORECASE
    )
}


# ------------------------------------------
# ATTACK DETECTION ENGINE
# ------------------------------------------

def detect_attack(payload):
    if not payload:
        return None

    for attack_name, pattern in REGEX_RULES.items():
        if pattern.search(payload):
            return attack_name

    return None


# ------------------------------------------
# FORENSIC LOGGER
# ------------------------------------------

def log_request(data):
    print("\n========== WAF REQUEST LOG ==========")
    print(f"Timestamp   : {data['timestamp']}")
    print(f"Source IP   : {data['ip']}")
    print(f"Method      : {data['method']}")
    print(f"URL Path    : {data['path']}")
    print(f"Query Params: {data['query_params']}")
    print(f"Form Data   : {data['form_data']}")
    print(f"JSON Data   : {data['json_data']}")
    print("=====================================\n")


# ------------------------------------------
# WAF INTERCEPTOR
# ------------------------------------------

@app.before_request
def waf_interceptor():

    try:
        request_data = {
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ip": request.remote_addr,
            "method": request.method,
            "path": request.path,
            "query_params": request.args.to_dict(),
            "form_data": request.form.to_dict(),
            "json_data": None
        }

        # Only check JSON for POST requests
        if request.method == "POST":
            request_data["json_data"] = request.get_json(silent=True)

        # Log every request
        log_request(request_data)

        # Default values
        g.attack_detected = False
        g.attack_type = None

        all_inputs = []

        # Form data
        for key, value in request.form.items():
            if value:
                all_inputs.append(value)

        # Query parameters
        for key, value in request.args.items():
            if value:
                all_inputs.append(value)

        # JSON body
        if request_data["json_data"]:
            if isinstance(request_data["json_data"], dict):
                for key, value in request_data["json_data"].items():
                    if isinstance(value, str):
                        all_inputs.append(value)

        # Scan all inputs
        for payload in all_inputs:
            attack_type = detect_attack(payload)

            if attack_type:
                print(" WAF ALERT ")
                print(f"Attack Type : {attack_type}")
                print(f"Payload     : {payload}")
                print(f"Source IP   : {request.remote_addr}")
                print("Request Blocked\n")

                g.attack_detected = True
                g.attack_type = attack_type
                break

    except Exception as e:
        print(f"WAF Error: {str(e)}")
        g.attack_detected = False
        g.attack_type = None


# ------------------------------------------
# HOME ROUTE
# ------------------------------------------

@app.route("/")
def home():
    return render_template(
        "index.html",
        status="Waiting for input"
    )


# ------------------------------------------
# DASHBOARD ROUTE
# ------------------------------------------

@app.route("/dashboard", methods=["POST"])
def dashboard():

    if g.attack_detected:
        return render_template(
            "index.html",
            status=f" Attack Detected: {g.attack_type}"
        )

    return render_template(
        "index.html",
        status=" Safe Input"
    )


# ------------------------------------------
# DATASET PAYLOAD TESTER
# ------------------------------------------

def dataset_test():

    try:
        dataset_path = os.path.join(
            os.path.dirname(__file__),
            "payload_dataset.txt"
        )

        with open(dataset_path, "r", encoding="utf-8") as f:
            payloads = [line.strip() for line in f if line.strip()]

    except FileNotFoundError:
        print("payload_dataset.txt not found.")
        return

    print("\nAvailable Payloads:\n")

    for i, payload in enumerate(payloads, start=1):
        print(f"{i}. {payload}")

    choice = input(
        "\nEnter payload number to test (or press Enter to skip): "
    )

    # If Enter is pressed → continue to Flask
    if not choice:
        print("\nStarting Flask server...\n")
        return

    try:
        index = int(choice) - 1
        payload = payloads[index]

    except:
        print("Invalid choice.")
        print("\nStarting Flask server...\n")
        return

    print(f"\nTesting payload: {payload}")

    result = detect_attack(payload)

    if result:
        print(f" ATTACK DETECTED → {result}")
    else:
        print(" SAFE INPUT")

    print("\nStarting Flask server...\n")


# ------------------------------------------
# SERVER ENTRY POINT
# ------------------------------------------

if __name__ == "__main__":

    # Show predefined payload prompts first
    dataset_test()

    # Then start Flask server
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
