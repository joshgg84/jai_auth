from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import hashlib
import secrets
import json
import os
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__, static_folder='public')
CORS(app)

# ============= DATABASE FILES =============
USERS_FILE = 'users.json'
API_KEYS_FILE = 'api_keys.json'

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)

def load_api_keys():
    if os.path.exists(API_KEYS_FILE):
        with open(API_KEYS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_api_keys(keys):
    with open(API_KEYS_FILE, 'w') as f:
        json.dump(keys, f, indent=2)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def generate_api_key():
    return f"jai_{secrets.token_urlsafe(32)}"

# ============= SESSION MANAGEMENT =============
active_sessions = {}  # session_token -> {'username': str, 'expiry': datetime}

def create_session(username):
    """Create a new session token for user"""
    session_token = hashlib.sha256(f"{username}{datetime.now().isoformat()}{secrets.token_hex(16)}".encode()).hexdigest()
    active_sessions[session_token] = {
        'username': username,
        'expiry': datetime.now() + timedelta(hours=24)
    }
    return session_token

def verify_session(session_token):
    """Verify if session token is valid"""
    if not session_token or session_token not in active_sessions:
        return None
    
    session = active_sessions[session_token]
    if datetime.now() > session['expiry']:
        del active_sessions[session_token]
        return None
    
    return session['username']

def require_session(f):
    """Decorator to require valid session token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        session_token = request.headers.get('X-Session-Token')
        
        if not session_token:
            return jsonify({'error': 'Session token required'}), 401
        
        username = verify_session(session_token)
        if not username:
            return jsonify({'error': 'Invalid or expired session'}), 401
        
        request.username = username
        request.session_token = session_token
        return f(*args, **kwargs)
    return decorated

# ============= USER ENDPOINTS =============

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
        return jsonify({'error': 'Username already exists'}), 400
    
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
    
    # Create session token
    session_token = create_session(username)
    
    return jsonify({
        'success': True,
        'session_token': session_token,
        'username': username
    })

@app.route('/api/logout', methods=['POST'])
def logout():
    data = request.json
    session_token = data.get('session_token')
    
    if session_token and session_token in active_sessions:
        del active_sessions[session_token]
    
    return jsonify({'success': True})

@app.route('/api/verify-session', methods=['POST'])
def verify_session_endpoint():
    """Verify session token (called by jai1)"""
    data = request.json
    session_token = data.get('session_token')
    
    username = verify_session(session_token)
    
    if not username:
        return jsonify({'valid': False}), 401
    
    return jsonify({
        'valid': True,
        'username': username
    })

# ============= API KEY MANAGEMENT =============

@app.route('/api/keys/create', methods=['POST'])
@require_session
def create_api_key():
    """Create a new API key for the logged-in user"""
    data = request.json
    key_name = data.get('name')
    tier = data.get('tier', 'free')
    
    if not key_name:
        return jsonify({'error': 'Key name required'}), 400
    
    # Tier limits (source of truth)
    tier_limits = {
        'free': {'rate': 2, 'daily': 100, 'price': 0},
        'pro': {'rate': 15, 'daily': 10000, 'price': 10000},
        'enterprise': {'rate': 1000, 'daily': None, 'price': 190000}
    }
    
    if tier not in tier_limits:
        return jsonify({'error': 'Invalid tier'}), 400
    
    limits = tier_limits[tier]
    
    # Generate new API key
    api_key = generate_api_key()
    
    keys = load_api_keys()
    keys[api_key] = {
        'name': key_name,
        'tier': tier,
        'limits': limits,
        'username': request.username,
        'created_at': datetime.now().isoformat(),
        'active': True,
        'requests': 0,
        'last_used': None
    }
    save_api_keys(keys)
    
    return jsonify({
        'success': True,
        'api_key': api_key,
        'key_id': api_key[:12] + '...',
        'tier': tier,
        'limits': limits
    })

@app.route('/api/keys/list', methods=['GET'])
@require_session
def list_api_keys():
    """List all API keys for the logged-in user"""
    keys = load_api_keys()
    user_keys = []
    
    for key, data in keys.items():
        if data.get('username') == request.username:
            user_keys.append({
                'key_preview': key[:20] + '...',
                'name': data.get('name'),
                'tier': data.get('tier'),
                'limits': data.get('limits'),
                'created_at': data.get('created_at'),
                'active': data.get('active', True),
                'requests': data.get('requests', 0)
            })
    
    return jsonify({'keys': user_keys, 'total': len(user_keys)})

@app.route('/api/keys/revoke', methods=['POST'])
@require_session
def revoke_api_key():
    """Revoke an API key"""
    data = request.json
    api_key = data.get('api_key')
    
    if not api_key:
        return jsonify({'error': 'API key required'}), 400
    
    keys = load_api_keys()
    
    if api_key not in keys:
        return jsonify({'error': 'API key not found'}), 404
    
    if keys[api_key].get('username') != request.username:
        return jsonify({'error': 'Unauthorized'}), 403
    
    keys[api_key]['active'] = False
    save_api_keys(keys)
    
    return jsonify({'success': True})

# ============= ENDPOINTS FOR JAI1 =============

@app.route('/api/validate-key', methods=['POST'])
def validate_key():
    """Called by jai1 to validate an API key and session"""
    data = request.json
    api_key = data.get('api_key')
    session_token = data.get('session_token')
    
    print(f"🔍 Validating key: {api_key[:20] if api_key else 'None'}... for session: {session_token[:20] if session_token else 'None'}...")
    
    # First verify session
    username = verify_session(session_token)
    if not username:
        print("❌ Invalid session")
        return jsonify({'valid': False, 'error': 'Invalid session'}), 401
    
    print(f"✅ Session valid for user: {username}")
    
    # Load API keys
    keys = load_api_keys()
    
    if api_key not in keys:
        print(f"❌ API key not found: {api_key[:20] if api_key else 'None'}...")
        return jsonify({'valid': False, 'error': 'Invalid API key'}), 401
    
    key_data = keys[api_key]
    print(f"✅ API key found: {key_data.get('name')} ({key_data.get('tier')})")
    
    # Check if key belongs to this user
    if key_data.get('username') != username:
        print(f"❌ Key belongs to {key_data.get('username')}, not {username}")
        return jsonify({'valid': False, 'error': 'API key does not belong to user'}), 403
    
    # Check if key is active
    if not key_data.get('active', True):
        print("❌ Key is deactivated")
        return jsonify({'valid': False, 'error': 'API key is deactivated'}), 401
    
    # Get limits from the key (source of truth)
    limits = key_data.get('limits', {'rate': 2, 'daily': 100})
    
    print(f"✅ Validation successful! Rate limit: {limits.get('rate')} req/min")
    
    return jsonify({
        'valid': True,
        'username': key_data.get('username'),
        'key_name': key_data.get('name'),
        'tier': key_data.get('tier'),
        'rate_per_minute': limits.get('rate', 2),
        'daily_limit': limits.get('daily', 100),
        'total_requests': key_data.get('requests', 0)
    })

@app.route('/api/track-usage', methods=['POST'])
def track_usage():
    """Called by jai1 to increment request count"""
    data = request.json
    api_key = data.get('api_key')
    
    if not api_key:
        return jsonify({'error': 'API key required'}), 400
    
    keys = load_api_keys()
    
    if api_key in keys:
        keys[api_key]['requests'] = keys[api_key].get('requests', 0) + 1
        keys[api_key]['last_used'] = datetime.now().isoformat()
        save_api_keys(keys)
        print(f"📊 Tracked usage for key: {api_key[:20]}... (Total: {keys[api_key]['requests']})")
    
    return jsonify({'success': True})

# ============= HEALTH CHECK =============

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy',
        'service': 'jai-api',
        'sessions': len(active_sessions),
        'total_keys': len(load_api_keys())
    })

# ============= STATIC FILES (Dashboard) =============

@app.route('/')
def index():
    return send_from_directory('public', 'signup.html')

@app.route('/<path:path>')
def static_files(path):
    return send_from_directory('public', path)

# ============= DEBUG ENDPOINT (remove in production) =============
@app.route('/debug/sessions', methods=['GET'])
def debug_sessions():
    """Debug endpoint to see active sessions (remove in production)"""
    sessions = {k: {'username': v['username'], 'expiry': v['expiry'].isoformat()} 
                for k, v in active_sessions.items()}
    return jsonify({
        'active_sessions': len(active_sessions),
        'sessions': sessions,
        'total_keys': len(load_api_keys())
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    
    print("\n" + "="*60)
    print("🔐 JAI-API SERVER STARTING")
    print("="*60)
    print(f"Port: {port}")
    print(f"Users file: {USERS_FILE}")
    print(f"API Keys file: {API_KEYS_FILE}")
    print(f"Active sessions: {len(active_sessions)}")
    print("\nEndpoints:")
    print("  POST /api/signup - Create account")
    print("  POST /api/login - Login (returns session_token)")
    print("  POST /api/logout - Logout")
    print("  POST /api/keys/create - Create API key (requires session)")
    print("  GET  /api/keys/list - List API keys (requires session)")
    print("  POST /api/keys/revoke - Revoke API key (requires session)")
    print("  POST /api/validate-key - Validate key for jai1")
    print("  POST /api/track-usage - Track usage for jai1")
    print("  GET  /health - Health check")
    print("="*60 + "\n")
    
    app.run(host='0.0.0.0', port=port)