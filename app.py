"""
Main Application Entrypoint: CNS Secure End-to-End Messaging System
Supports dual HTTP (port 5000) and HTTPS/TLS (port 5443) execution modes.
"""
import os
import sys
import argparse
from pathlib import Path

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

from flask import Flask, render_template, redirect, url_for, session

from database import init_db
from routes.auth_routes import auth_bp
from routes.dh_routes import dh_bp
from routes.message_routes import msg_bp
from routes.attack_routes import attack_bp
from generate_cert import generate_self_signed_cert

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "cns-super-secret-educational-session-key-2026")

# Register Blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(dh_bp)
app.register_blueprint(msg_bp)
app.register_blueprint(attack_bp)

# Page Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/chat')
def chat_page():
    return render_template('chat.html')

@app.route('/attacks')
def attacks_page():
    return render_template('attack_demo.html')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="CNS Secure Messaging Server")
    parser.add_argument('--https', action='store_true', help="Run in HTTPS/TLS mode with SSL certificate")
    parser.add_argument('--port', type=int, default=None, help="Port to listen on (default: 5000 for HTTP, 5443 for HTTPS)")
    parser.add_argument('--host', type=str, default='127.0.0.1', help="Host to bind to")
    args = parser.parse_args()

    # Initialize SQLite Database
    init_db()

    if args.https:
        cert_path = Path("cert.pem")
        key_path = Path("key.pem")
        if not cert_path.exists() or not key_path.exists():
            print("[*] TLS Certificates not found. Generating self-signed certificates...")
            generate_self_signed_cert(str(cert_path), str(key_path))

        port = args.port or 5443
        print("\n=======================================================")
        print("[+] CNS SECURE MESSAGING SERVER (HTTPS/TLS MODE)")
        print(f"[*] Serving on: https://{args.host}:{port}")
        print("[*] Transport Encryption: TLS v1.3 / X.509 Certificate")
        print("=======================================================\n")
        app.run(host=args.host, port=port, ssl_context=(str(cert_path), str(key_path)), debug=True)
    else:
        port = args.port or 5000
        print("\n=======================================================")
        print("[+] CNS SECURE MESSAGING SERVER (HTTP RELAY MODE)")
        print(f"[*] Serving on: http://{args.host}:{port}")
        print("[*] Application-Layer E2EE: Active (AES-256-CBC + HMAC)")
        print("=======================================================\n")
        app.run(host=args.host, port=port, debug=True)
