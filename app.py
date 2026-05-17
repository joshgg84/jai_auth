from flask import Flask, request, jsonify, send_from_directory
import hashlib
import json
import os
from datetime import datetime
from functools import wraps

app = Flask(__name__, static_folder='public')

# ============= DATABASE =============
USERS_FILE = 'users.json'

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# ============= AUTH DECORATOR =============
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'error': 'Authentication required'}), 401
        
        # Simple session token check
        username = auth_header.replace('Bearer ', '')
        users = load_users()
        
        if username not in users:
            return jsonify({'error': 'Invalid session'}), 401
        
        request.user = users[username]
        return f(*args, **kwargs)
    return decorated

# ============= PUBLIC ENDPOINTS =============

@app.route('/')
def index():
    return send_from_directory('public', 'signup.html')

@app.route('/<path:path>')
def static_files(path):
    return send_from_directory('public', path)

@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    
    if not username or not email or not password:
        return jsonify({'error': 'All fields required'}), 400
    
    users = load_users()
    
    if username in users:
        return jsonify({'error': 'Username exists'}), 400
    
    users[username] = {
        'username': username,
        'email': email,
        'password_hash': hash_password(password),
        'created_at': datetime.now().isoformat()
    }
    save_users(users)
    
    return jsonify({'success': True, 'username': username})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    users = load_users()
    
    if username not in users:
        return jsonify({'error': 'Invalid credentials'}), 401
    
    user = users[username]
    
    if user['password_hash'] != hash_password(password):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    return jsonify({'success': True, 'username': username})

@app.route('/api/user/<username>', methods=['GET'])
@require_auth
def get_user(username):
    if username != request.user['username']:
        return jsonify({'error': 'Unauthorized'}), 403
    
    return jsonify({
        'username': request.user['username'],
        'email': request.user['email'],
        'created_at': request.user['created_at']
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    app.run(host='0.0.0.0', port=port)