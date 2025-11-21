"""
Test Web Application for WAF Testing
This application provides various endpoints to test WAF security features.
"""

from flask import Flask, request, render_template, jsonify, redirect, url_for
import os
import sys

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.core.waf import PyWAF
from src.middleware.request_parser import RequestParser

app = Flask(__name__)

# Initialize WAF
waf = PyWAF()

@app.before_request
def waf_middleware():
    """Apply WAF protection to all incoming requests"""
    client_ip = request.remote_addr
    
    # Parse the request
    parsed_request = RequestParser.parse_request(request)
    
    # Process request through WAF
    waf_response = waf.process_request(parsed_request)
    
    if not waf_response.allowed:
        return jsonify({
            'error': 'Request blocked by WAF',
            'reason': waf_response.reason,
            'ip': client_ip
        }), 403


@app.route('/')
def index():
    """Home page"""
    return render_template('index.html')


@app.route('/about')
def about():
    """About page"""
    return render_template('about.html')


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    """Contact form - Test XSS and SQL Injection"""
    if request.method == 'POST':
        name = request.form.get('name', '')
        email = request.form.get('email', '')
        message = request.form.get('message', '')
        
        return jsonify({
            'status': 'success',
            'message': 'Thank you for your message!',
            'data': {
                'name': name,
                'email': email,
                'message': message
            }
        })
    
    return render_template('contact.html')


@app.route('/search')
def search():
    """Search endpoint - Test XSS in query parameters"""
    query = request.args.get('q', '')
    return render_template('search.html', query=query)


@app.route('/user/<username>')
def user_profile(username):
    """User profile - Test path traversal and XSS"""
    return render_template('profile.html', username=username)


@app.route('/api/users')
def api_users():
    """API endpoint - Test SQL Injection in query parameters"""
    user_id = request.args.get('id', '')
    filter_by = request.args.get('filter', '')
    
    # Simulated database query (vulnerable pattern for testing)
    return jsonify({
        'users': [
            {'id': 1, 'name': 'Alice', 'email': 'alice@example.com'},
            {'id': 2, 'name': 'Bob', 'email': 'bob@example.com'},
            {'id': 3, 'name': 'Charlie', 'email': 'charlie@example.com'}
        ],
        'query_params': {
            'id': user_id,
            'filter': filter_by
        }
    })


@app.route('/files')
def view_file():
    """File viewer - Test path traversal"""
    filename = request.args.get('file', 'index.html')
    return jsonify({
        'requested_file': filename,
        'message': 'File access would be processed here'
    })


@app.route('/download')
def download():
    """Download endpoint - Test path traversal"""
    path = request.args.get('path', '')
    return jsonify({
        'download_path': path,
        'message': 'Download would be processed here'
    })


@app.route('/admin/dashboard')
def admin_dashboard():
    """Admin dashboard - Test authentication bypass"""
    return render_template('admin.html')


@app.route('/api/data', methods=['POST'])
def api_data():
    """API endpoint for POST data - Test JSON injection"""
    data = request.get_json()
    return jsonify({
        'status': 'received',
        'data': data
    })


@app.route('/comment', methods=['POST'])
def add_comment():
    """Comment submission - Test XSS in POST data"""
    comment = request.form.get('comment', '')
    author = request.form.get('author', '')
    
    return jsonify({
        'status': 'success',
        'comment': comment,
        'author': author
    })


@app.route('/waf/status')
def waf_status():
    """Get WAF status and statistics"""
    return jsonify({
        'status': 'active',
        'message': 'WAF is protecting this application'
    })


@app.route('/test/payloads')
def test_payloads():
    """Page with example malicious payloads for testing"""
    return render_template('test_payloads.html')


@app.errorhandler(403)
def forbidden(error):
    """Custom 403 error handler"""
    return render_template('403.html'), 403


@app.errorhandler(404)
def not_found(error):
    """Custom 404 error handler"""
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    """Custom 500 error handler"""
    return render_template('500.html'), 500


if __name__ == '__main__':
    print("=" * 60)
    print("WAF-Protected Test Web Application")
    print("=" * 60)
    print("Starting server on http://127.0.0.1:5000")
    print("Press CTRL+C to stop the server")
    print("=" * 60)
    
    app.run(debug=True, host='127.0.0.1', port=5000)
