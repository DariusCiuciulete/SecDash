"""
Vulnerable test web application for security scanning
This app contains intentional vulnerabilities for testing purposes only.
DO NOT deploy in production!
"""
from flask import Flask, request, render_template_string, redirect, session, make_response
import os
import sqlite3
import subprocess
import pickle
import base64

app = Flask(__name__)
app.secret_key = 'insecure_test_key_do_not_use'

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect('test_app.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT
        )
    ''')
    cursor.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'password123', 'admin@test.com')")
    cursor.execute("INSERT OR IGNORE INTO users VALUES (2, 'user', 'pass', 'user@test.com')")
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def home():
    return '''
    <html>
    <head><title>SecDash Test Web Application</title></head>
    <body>
        <h1>🔒 SecDash Test Web Application</h1>
        <p><b>⚠️ WARNING:</b> This application contains intentional vulnerabilities for testing purposes!</p>
        
        <h2>Test Features:</h2>
        <ul>
            <li><a href="/search">🔍 Search (XSS Vulnerable)</a></li>
            <li><a href="/login">🔐 Login (SQL Injection Vulnerable)</a></li>
            <li><a href="/upload">📁 File Upload</a></li>
            <li><a href="/admin">👤 Admin Panel</a></li>
            <li><a href="/api/users">📊 API Endpoint</a></li>
            <li><a href="/redirect">🔗 Open Redirect</a></li>
            <li><a href="/serialize">🧬 Insecure Deserialization</a></li>
            <li><a href="/command">💻 Command Injection</a></li>
        </ul>
        
        <h2>Scan Targets:</h2>
        <p>Use the following URLs for different scan types:</p>
        <ul>
            <li><strong>ZAP Baseline:</strong> http://127.0.0.1:8080/</li>
            <li><strong>ZAP Full Scan:</strong> http://127.0.0.1:8080/</li>
            <li><strong>Nikto Scan:</strong> http://127.0.0.1:8080/</li>
        </ul>
    </body>
    </html>
    '''

@app.route('/search')
def search():
    query = request.args.get('q', '')
    # XSS vulnerability - unsafe rendering
    return f'''
    <html>
    <head><title>Search Results</title></head>
    <body>
        <h2>🔍 Search Results</h2>
        <form method="GET">
            <input name="q" value="{query}" placeholder="Search..." size="50">
            <button type="submit">Search</button>
        </form>
        <p>You searched for: <strong>{query}</strong></p>
        <p>Try: <code>?q=&lt;script&gt;alert('XSS')&lt;/script&gt;</code></p>
        <a href="/">← Back to Home</a>
    </body>
    </html>
    '''

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # SQL injection vulnerability - unsafe query construction
        conn = sqlite3.connect('test_app.db')
        cursor = conn.cursor()
        
        # Vulnerable query
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        
        try:
            cursor.execute(query)
            user = cursor.fetchone()
            conn.close()
            
            if user:
                session['user_id'] = user[0]
                return f'''
                <h2>✅ Login Successful</h2>
                <p>Welcome, {user[1]}!</p>
                <p>Query executed: <code>{query}</code></p>
                <a href="/admin">Go to Admin Panel</a> | <a href="/">Home</a>
                '''
            else:
                return f'''
                <h2>❌ Login Failed</h2>
                <p>Query executed: <code>{query}</code></p>
                <p>Try: username: <code>admin' OR '1'='1</code>, password: anything</p>
                <a href="/login">Try Again</a> | <a href="/">Home</a>
                '''
        except Exception as e:
            conn.close()
            return f'''
            <h2>💥 Database Error</h2>
            <p>Error: {str(e)}</p>
            <p>Query: <code>{query}</code></p>
            <a href="/login">Try Again</a>
            '''
    
    return '''
    <html>
    <head><title>Login</title></head>
    <body>
        <h2>🔐 Login</h2>
        <form method="post">
            <p>Username: <input name="username" required style="width:200px"></p>
            <p>Password: <input name="password" type="password" required style="width:200px"></p>
            <p><button type="submit">Login</button></p>
        </form>
        <p><strong>Test Credentials:</strong></p>
        <ul>
            <li>admin / password123</li>
            <li>user / pass</li>
        </ul>
        <p><strong>SQL Injection Test:</strong> Try username: <code>admin' OR '1'='1</code></p>
        <a href="/">← Back to Home</a>
    </body>
    </html>
    '''

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        file = request.files.get('file')
        if file:
            # Unsafe file upload - no validation
            filename = file.filename
            file.save(f'/tmp/{filename}')
            return f'''
            <h2>📁 File Uploaded</h2>
            <p>File "{filename}" uploaded successfully to /tmp/</p>
            <p>⚠️ No file type validation performed!</p>
            <a href="/upload">Upload Another</a> | <a href="/">Home</a>
            '''
    
    return '''
    <html>
    <head><title>File Upload</title></head>
    <body>
        <h2>📁 File Upload</h2>
        <form method="post" enctype="multipart/form-data">
            <p>File: <input type="file" name="file" required></p>
            <p><button type="submit">Upload</button></p>
        </form>
        <p>⚠️ This upload has no security validation!</p>
        <a href="/">← Back to Home</a>
    </body>
    </html>
    '''

@app.route('/admin')
def admin():
    return '''
    <html>
    <head><title>Admin Panel</title></head>
    <body>
        <h2>👤 Admin Panel</h2>
        <p>This is a sensitive admin area with no authentication!</p>
        <ul>
            <li><a href="/admin/users">👥 User Management</a></li>
            <li><a href="/admin/config">⚙️ System Config</a></li>
            <li><a href="/admin/logs">📋 System Logs</a></li>
        </ul>
        <a href="/">← Back to Home</a>
    </body>
    </html>
    '''

@app.route('/api/users')
def api_users():
    conn = sqlite3.connect('test_app.db')
    cursor = conn.cursor()
    cursor.execute("SELECT username, email FROM users")
    users = cursor.fetchall()
    conn.close()
    
    # Return sensitive data without authentication
    user_list = [{"username": u[0], "email": u[1]} for u in users]
    
    response = make_response(str(user_list))
    response.headers['Content-Type'] = 'application/json'
    # Missing security headers
    return response

@app.route('/redirect')
def redirect_test():
    url = request.args.get('url', 'https://example.com')
    # Open redirect vulnerability
    return redirect(url)

@app.route('/serialize', methods=['GET', 'POST'])
def serialize_test():
    if request.method == 'POST':
        data = request.form.get('data', '')
        try:
            # Insecure deserialization
            decoded = base64.b64decode(data)
            obj = pickle.loads(decoded)
            return f"<h2>Deserialized object: {obj}</h2><a href='/serialize'>Back</a>"
        except Exception as e:
            return f"<h2>Error: {e}</h2><a href='/serialize'>Back</a>"
    
    return '''
    <h2>🧬 Insecure Deserialization</h2>
    <form method="post">
        <p>Base64 encoded pickle data:</p>
        <textarea name="data" rows="4" cols="50"></textarea><br>
        <button type="submit">Deserialize</button>
    </form>
    <a href="/">← Back to Home</a>
    '''

@app.route('/command')
def command_injection():
    cmd = request.args.get('cmd', 'echo "Hello World"')
    try:
        # Command injection vulnerability
        result = subprocess.check_output(cmd, shell=True, text=True)
        return f'''
        <h2>💻 Command Execution</h2>
        <p>Command: <code>{cmd}</code></p>
        <pre>{result}</pre>
        <p>Try: <code>?cmd=ls -la</code> or <code>?cmd=whoami</code></p>
        <a href="/">← Back to Home</a>
        '''
    except Exception as e:
        return f'''
        <h2>💥 Command Error</h2>
        <p>Command: <code>{cmd}</code></p>
        <p>Error: {str(e)}</p>
        <a href="/">← Back to Home</a>
        '''

@app.route('/robots.txt')
def robots():
    return '''User-agent: *
Disallow: /admin/
Disallow: /api/
Disallow: /backup/
# Hidden directories for testing
'''

@app.route('/.htaccess')
def htaccess():
    return '''# Configuration file exposed
RewriteEngine On
# Sensitive configuration here
'''

if __name__ == '__main__':
    print("🚀 Starting SecDash Test Web Application")
    print("📡 URL: http://127.0.0.1:8080")
    print("⚠️  WARNING: This app contains intentional vulnerabilities!")
    print("🔒 Use only for security testing purposes")
    app.run(host='127.0.0.1', port=8080, debug=True)
