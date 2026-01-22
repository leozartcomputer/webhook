import hmac
from flask import Flask, request, abort
import os
import hashlib
import mysql.connector
import json
import requests
import sys


config = {
    'user': os.getenv("PW_user", ""),
    'password': os.getenv("PW_password", ""),
    'host': os.getenv("PW_host", ""),
    'database': os.getenv("PW_database", ""),
    'port': os.getenv("PW_portdb", ""),
}

def headersSupa():
    return {
        "apikey":os.getenv("PW_apikey", "")
    }


app = Flask(__name__)
SERVICE_SECRET= os.getenv("SERVICE_SECRET", "")
@app.route('/', methods=['POST'])
def index():
    global SERVICE_SECRET
    signature = request.headers.get("Ms-Signature")

    # Obtener el payload como bytes crudos
    payload = request.get_data()

    # Calcular la firma local
    expected_sig = "sha256=" + hmac.new(
        SERVICE_SECRET.encode(), payload, hashlib.sha256
    ).hexdigest().upper()
        
    # Validar la firma usando comparación segura
    if not signature:
        print("Missing signature header", file=sys.stderr)
        return "Unauthorized: Missing signature", 401
    
    # Comparación segura contra timing attacks
    if not hmac.compare_digest(expected_sig, signature):
        print("Invalid signature", file=sys.stderr)
        return "Unauthorized: Invalid signature", 401
    
    print("Signature validated successfully", file=sys.stderr)
    print("-----------------")
    # Procesar el payload
    d = request.get_json()
    data = {
        "payload":d,
        "env":"PROD"
    }
    SUPABASE_URL = os.getenv("PW_urlSupa","")
    url = f"{SUPABASE_URL}webhook_chq_dup"
    #print(url, file=sys.stderr)
    response = requests.post(url, json=data, headers=headersSupa())
    if response.status_code not in [200, 201, 204, 202]:
        print(f"Failed to log error: {response.status_code} - {response.text}", file=sys.stderr)
    
    url = "http://prefect-worker:4200/api/deployments/e7ba2f03-1fe8-4e0c-8531-b560568f4e14/create_flow_run"

    # Definimos el cuerpo de la petición (el "null" de JSON es "None" en Python)
    payload = {
        "state": None
    }

    # Definimos las cabeceras
    headers = {
        "Content-Type": "application/json"
    }
    response = requests.post(url, json=payload, headers=headers)
    return "OK", 200

if __name__ == '__main__':
    app.debug = True
    app.run(host="0.0.0.0", port=5032)