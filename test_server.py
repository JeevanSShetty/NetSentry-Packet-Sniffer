#!/usr/bin/env python3
"""
Vulnerable HTTP Server for Testing NetSentry
WARNING: Intentionally insecure - for testing only!
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs

class TestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        html = '''
<!DOCTYPE html>
<html>
<head>
    <title>NetSentry Test Server</title>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            max-width: 600px; 
            margin: 50px auto; 
            padding: 20px;
            background: #f5f5f5;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 { color: #d32f2f; }
        .warning {
            background: #fff3cd;
            border: 2px solid #ffc107;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        input {
            width: 100%;
            padding: 10px;
            margin: 8px 0;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
        }
        button {
            background: #d32f2f;
            color: white;
            padding: 12px 30px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
            margin-top: 10px;
        }
        button:hover { background: #b71c1c; }
        .form-section {
            margin: 20px 0;
            padding: 20px;
            border: 1px solid #eee;
            border-radius: 5px;
        }
        h3 { color: #555; margin-top: 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>⚠️ Vulnerable Test Server</h1>
        <div class="warning">
            <strong>WARNING:</strong> This server sends data over UNENCRYPTED HTTP!<br>
            Perfect for testing NetSentry packet capture.
        </div>

        <!-- Login Form -->
        <div class="form-section">
            <h3>🔐 Login Form</h3>
            <form method="POST" action="/login">
                <input type="text" name="username" placeholder="Username (e.g., admin)" required>
                <input type="password" name="password" placeholder="Password (e.g., Secret123)" required>
                <input type="email" name="email" placeholder="Email (e.g., test@example.com)" required>
                <button type="submit">Login (HTTP)</button>
            </form>
        </div>

        <!-- API Form -->
        <div class="form-section">
            <h3>🔑 API Key Form</h3>
            <form method="POST" action="/api">
                <input type="text" name="api_key" 
                       placeholder="API Key (e.g., sk_test_abcdefghijklmnopqrstuvwxyz123456)" required>
                <input type="text" name="secret_token" 
                       placeholder="Secret Token (e.g., ghp_1234567890abcdefghijklmnopqr)" required>
                <button type="submit">Submit API Key (HTTP)</button>
            </form>
        </div>

        <!-- Personal Info Form -->
        <div class="form-section">
            <h3>👤 Personal Information</h3>
            <form method="POST" action="/register">
                <input type="text" name="fullname" placeholder="Full Name (e.g., John Doe)" required>
                <input type="email" name="email" placeholder="Email (e.g., john@example.com)" required>
                <input type="text" name="ssn" placeholder="SSN (e.g., 123-45-6789)" required>
                <input type="tel" name="phone" placeholder="Phone (e.g., 555-123-4567)" required>
                <button type="submit">Register (HTTP)</button>
            </form>
        </div>

        <!-- Payment Form -->
        <div class="form-section">
            <h3>💳 Payment Form</h3>
            <form method="POST" action="/payment">
                <input type="text" name="card_number" 
                       placeholder="Card Number (e.g., 4532-1488-0343-6467)" required>
                <input type="text" name="cvv" placeholder="CVV (e.g., 123)" required>
                <input type="text" name="expiry" placeholder="Expiry (e.g., 12/25)" required>
                <button type="submit">Pay Now (HTTP)</button>
            </form>
        </div>

        <!-- Combined Form -->
        <div class="form-section">
            <h3>🎯 Everything at Once!</h3>
            <form method="POST" action="/everything">
                <input type="email" name="email" placeholder="Email" value="test@company.com">
                <input type="password" name="password" placeholder="Password" value="MySecret123">
                <input type="text" name="api_key" placeholder="API Key" 
                       value="sk_live_abcdefghijklmnopqrstuvwxyz1234567890">
                <input type="text" name="ssn" placeholder="SSN" value="987-65-4321">
                <input type="text" name="card" placeholder="Card" value="4532-1488-0343-6467">
                <input type="text" name="phone" placeholder="Phone" value="555-867-5309">
                <button type="submit">Submit All (HTTP)</button>
            </form>
        </div>
    </div>
</body>
</html>
        '''
        self.wfile.write(html.encode())
    
    def do_POST(self):
        # Read POST data
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        
        # Parse form data
        params = parse_qs(post_data)
        
        # Send response
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        response = f'''
<!DOCTYPE html>
<html>
<head>
    <title>Data Received</title>
    <style>
        body {{ 
            font-family: Arial, sans-serif; 
            max-width: 600px; 
            margin: 50px auto; 
            padding: 20px;
        }}
        .success {{
            background: #d4edda;
            border: 2px solid #28a745;
            padding: 20px;
            border-radius: 5px;
        }}
        pre {{
            background: #f5f5f5;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
        }}
        a {{
            display: inline-block;
            margin-top: 20px;
            padding: 10px 20px;
            background: #007bff;
            color: white;
            text-decoration: none;
            border-radius: 4px;
        }}
    </style>
</head>
<body>
    <div class="success">
        <h2>✅ Data Received Successfully!</h2>
        <p><strong>NetSentry should have captured this data!</strong></p>
        <p>Path: {self.path}</p>
        <h3>Submitted Data:</h3>
        <pre>{post_data}</pre>
    </div>
    <a href="/">← Back to Forms</a>
</body>
</html>
        '''
        self.wfile.write(response.encode())
    
    def log_message(self, format, *args):
        # Custom logging
        print(f"[SERVER] {self.command} {self.path}")

if __name__ == '__main__':
    PORT = 8080
    print("=" * 70)
    print(" " * 15 + "VULNERABLE TEST SERVER")
    print("=" * 70)
    print(f"\n[+] Server starting on http://localhost:{PORT}")
    print(f"[!] WARNING: This server is INTENTIONALLY INSECURE!")
    print(f"[!] All data sent over UNENCRYPTED HTTP")
    print(f"[+] Perfect for testing NetSentry packet capture\n")
    print("=" * 70)
    print("\nInstructions:")
    print("  1. Keep this server running")
    print("  2. In another terminal, run:")
    print("     sudo python3 netsentry_txt.py -i lo")
    print("  3. Open browser to http://localhost:8080")
    print("  4. Submit forms with fake data")
    print("  5. Check alerts.txt for captured data")
    print("\nPress Ctrl+C to stop the server")
    print("=" * 70 + "\n")
    
    try:
        server = HTTPServer(('localhost', PORT), TestHandler)
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n\n[+] Server stopped")
