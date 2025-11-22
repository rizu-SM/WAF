"""
Vulnerable Web Application for WAF Testing
This application has intentional security vulnerabilities to demonstrate WAF protection.
NEVER use this in production without the WAF!
"""
from flask import Flask, request, render_template, jsonify, make_response, redirect, url_for, session
import sqlite3
import os
from datetime import datetime

# Import WAF components
from src.core.waf import get_waf, WAFRequest
from src.middleware.request_parser import RequestParser

app = Flask(__name__)
app.secret_key = 'vulnerable-secret-key-change-in-production'

# Initialize WAF
waf = get_waf()

# Database setup
def init_db():
    """Initialize SQLite database with sample data"""
    conn = sqlite3.connect('vulnerable_app.db')
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user'
        )
    ''')
    
    # Create posts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            author TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Insert sample data
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
                      ('admin', 'admin123', 'admin@example.com', 'admin'))
        cursor.execute("INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
                      ('john', 'password', 'john@example.com', 'user'))
        cursor.execute("INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
                      ('alice', 'alice123', 'alice@example.com', 'user'))
    
    cursor.execute("SELECT COUNT(*) FROM posts")
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO posts (title, content, author) VALUES (?, ?, ?)",
                      ('Welcome Post', 'Welcome to our vulnerable website!', 'admin'))
        cursor.execute("INSERT INTO posts (title, content, author) VALUES (?, ?, ?)",
                      ('Security Tips', 'Always use strong passwords!', 'john'))
    
    conn.commit()
    conn.close()

# WAF Middleware
@app.before_request
def waf_check():
    """Check all requests through WAF before processing"""
    # Parse Flask request to WAFRequest
    waf_request = RequestParser.parse_request(request)
    
    # Process through WAF
    waf_response = waf.process_request(waf_request)
    
    # Block if WAF denies request
    if not waf_response.allowed:
        if waf_response.action == "block":
            return jsonify({
                "error": "Request blocked by WAF",
                "reason": waf_response.reason,
                "attack_type": waf_response.details.get('attack_type', 'unknown'),
                "status": "blocked"
            }), 403
        elif waf_response.action == "challenge":
            return jsonify({
                "error": "Security challenge required",
                "reason": waf_response.reason,
                "status": "challenge"
            }), 429
    
    # Request allowed - continue processing
    return None

# Routes

@app.route('/')
def index():
    """Home page"""
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page - VULNERABLE TO SQL INJECTION"""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # VULNERABLE: Direct SQL query without parameterization
        conn = sqlite3.connect('vulnerable_app.db')
        cursor = conn.cursor()
        
        # This is intentionally vulnerable to SQL injection
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        
        try:
            cursor.execute(query)
            user = cursor.fetchone()
            conn.close()
            
            if user:
                session['user_id'] = user[0]
                session['username'] = user[1]
                session['role'] = user[4]
                return redirect(url_for('dashboard'))
            else:
                return render_template('login.html', error="Invalid credentials")
        except sqlite3.Error as e:
            conn.close()
            return render_template('login.html', error=f"Database error: {str(e)}")
    
    return render_template('login.html')

@app.route('/search')
def search():
    """Search page - VULNERABLE TO XSS"""
    query = request.args.get('q', '')
    
    conn = sqlite3.connect('vulnerable_app.db')
    cursor = conn.cursor()
    
    # Safe SQL query (but XSS vulnerable in template)
    cursor.execute("SELECT * FROM posts WHERE title LIKE ? OR content LIKE ?", 
                   (f'%{query}%', f'%{query}%'))
    results = cursor.fetchall()
    conn.close()
    
    # VULNERABLE: Passing unsanitized input to template
    return render_template('search.html', query=query, results=results)

@app.route('/files')
def view_file():
    """File viewer - VULNERABLE TO PATH TRAVERSAL"""
    filename = request.args.get('file', 'welcome.txt')
    
    # VULNERABLE: No path validation
    try:
        with open(filename, 'r') as f:
            content = f.read()
        return render_template('file_viewer.html', filename=filename, content=content)
    except Exception as e:
        return render_template('file_viewer.html', filename=filename, 
                             content=f"Error reading file: {str(e)}")

@app.route('/dashboard')
def dashboard():
    """User dashboard"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('vulnerable_app.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM posts ORDER BY created_at DESC")
    posts = cursor.fetchall()
    conn.close()
    
    return render_template('dashboard.html', posts=posts, username=session.get('username'))

@app.route('/post', methods=['POST'])
def create_post():
    """Create new post - VULNERABLE TO XSS"""
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    title = request.form.get('title', '')
    content = request.form.get('content', '')
    
    conn = sqlite3.connect('vulnerable_app.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO posts (title, content, author) VALUES (?, ?, ?)",
                   (title, content, session.get('username')))
    conn.commit()
    conn.close()
    
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    """Logout"""
    session.clear()
    return redirect(url_for('index'))

@app.route('/api/users')
def api_users():
    """API endpoint - VULNERABLE TO SQL INJECTION via query params"""
    user_id = request.args.get('id', '')
    
    conn = sqlite3.connect('vulnerable_app.db')
    cursor = conn.cursor()
    
    if user_id:
        # VULNERABLE: SQL injection in API
        query = f"SELECT id, username, email, role FROM users WHERE id={user_id}"
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()
        
        if user:
            return jsonify({
                "id": user[0],
                "username": user[1],
                "email": user[2],
                "role": user[3]
            })
        else:
            return jsonify({"error": "User not found"}), 404
    else:
        cursor.execute("SELECT id, username, email, role FROM users")
        users = cursor.fetchall()
        conn.close()
        
        return jsonify([{
            "id": u[0],
            "username": u[1],
            "email": u[2],
            "role": u[3]
        } for u in users])

@app.route('/waf/stats')
def waf_stats():
    """WAF statistics dashboard"""
    stats = waf.get_statistics()
    health = waf.health_check()
    recent_events = waf.get_recent_events(limit=50)
    
    return render_template('waf_stats.html', stats=stats, health=health, events=recent_events)

@app.route('/api/waf/stats')
def api_waf_stats():
    """WAF statistics API"""
    return jsonify({
        "stats": waf.get_statistics(),
        "health": waf.health_check()
    })

@app.route('/api/waf/reload', methods=['POST'])
def reload_waf_config():
    """Reload WAF configuration"""
    if waf.reload_configuration():
        return jsonify({"status": "success", "message": "Configuration reloaded"})
    else:
        return jsonify({"status": "error", "message": "Failed to reload configuration"}), 500

if __name__ == '__main__':
    # Initialize database
    print("🔧 Initializing database...")
    init_db()
    print("✅ Database initialized")
    
    print("\n" + "=" * 70)
    print("🚀 Starting Vulnerable Web Application with WAF Protection")
    print("=" * 70)
    print("\n⚠️  WARNING: This application has intentional vulnerabilities!")
    print("    It should ONLY be used for testing the WAF.\n")
    print("📊 Access WAF Statistics: http://localhost:5000/waf/stats")
    print("🏠 Home Page: http://localhost:5000/")
    print("\n💡 Test Credentials:")
    print("    Username: admin | Password: admin123")
    print("    Username: john  | Password: password")
    print("\n" + "=" * 70 + "\n")
    
    # Run Flask app
    app.run(debug=True, host='0.0.0.0', port=5000)
