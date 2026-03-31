from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, make_response
from flask_sock import Sock
import sqlite3
import json
import requests
import csv
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
import time
import socket
import hashlib
import io
import subprocess
from apscheduler.schedulers.background import BackgroundScheduler
from utils.docker_manager import start_container, stop_container, resume_container, remove_container, get_container_status, LAB_CONFIGS, get_client, get_lab_network_name, ensure_lab_network, prune_user_network_if_unused

app = Flask(__name__)
sock = Sock(app)
app.secret_key = 'super_secret_cyber_lab_key'
DB_PATH = 'database.db'

def is_lab_ready(port, path=''):
    url = f"http://127.0.0.1:{port}{path}"
    try:
        response = requests.get(url, timeout=2, allow_redirects=True)
        return response.status_code < 500
    except requests.RequestException:
        return False

def is_port_available(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(('0.0.0.0', port))
        return True
    except OSError:
        return False
    finally:
        sock.close()

def is_port_listening(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    try:
        return sock.connect_ex(('127.0.0.1', port)) == 0
    except OSError:
        return False
    finally:
        sock.close()

def get_next_available_port(conn, start_port=3001, max_attempts=1000):
    used_ports = {
        row['port']
        for row in conn.execute('SELECT port FROM containers').fetchall()
        if row['port'] is not None
    }

    port = start_port
    attempts = 0
    while attempts < max_attempts:
        if port not in used_ports and is_port_available(port):
            return port
        port += 1
        attempts += 1

    raise Exception('No available lab ports found in the configured range.')

def build_container_view(container_record, host):
    real_status = get_container_status(container_record['container_id'])
    lab_type = dict(container_record).get('lab_type', 'juice-shop')
    lab_conf = LAB_CONFIGS.get(lab_type, {})
    access_mode = lab_conf.get('access_mode', 'web')
    lab_path = lab_conf.get('entry_path', '')
    access_url = f"http://{host}:{container_record['port']}{lab_path}" if access_mode == 'web' else None
    is_ready = real_status == 'running' if access_mode != 'web' else (real_status == 'running' and is_lab_ready(container_record['port'], lab_path))
    return {
        'id': container_record['id'],
        'container_id': container_record['container_id'],
        'container_short_id': container_record['container_id'][:12],
        'port': container_record['port'],
        'status': real_status,
        'db_status': container_record['status'],
        'lab_type': lab_type,
        'lab_name': lab_conf.get('name', lab_type.upper()),
        'access_mode': access_mode,
        'lab_path': lab_path,
        'access_url': access_url,
        'is_ready': is_ready
    }

def get_lab_proxy_profile(container):
    lab_type = container.get('lab_type') if container else None
    access_url = container.get('access_url') if container else None
    port = container.get('port') if container else None

    profiles = {
        'juice-shop': {
            'mode': 'burp-http',
            'headline': 'Burp workflow for Juice Shop',
            'tool': 'Burp Suite Community',
            'focus': 'Auth flows, hidden parameters, token/cookie tampering, replay in Repeater.'
        },
        'dvwa': {
            'mode': 'burp-http',
            'headline': 'Burp workflow for DVWA',
            'tool': 'Burp Suite Community',
            'focus': 'GET/POST parameter manipulation, CSRF token handling, SQLi/XSS payload iteration.'
        },
        'bwapp': {
            'mode': 'burp-http',
            'headline': 'Burp workflow for bWAPP',
            'tool': 'Burp Suite Community',
            'focus': 'Form mutation, cookie edits, tamper with hidden fields, replay attacks in Repeater.'
        },
        'webgoat': {
            'mode': 'burp-http',
            'headline': 'Burp workflow for WebGoat',
            'tool': 'Burp Suite Community',
            'focus': 'Exercise request mutation lesson-by-lesson; inspect headers, body, and cookies.'
        },
        'mutillidae': {
            'mode': 'burp-http',
            'headline': 'Burp workflow for Mutillidae',
            'tool': 'Burp Suite Community',
            'focus': 'Parameter tampering and payload testing across classic vulnerable endpoints.'
        },
        'xvwa': {
            'mode': 'burp-http',
            'headline': 'Burp workflow for XVWA',
            'tool': 'Burp Suite Community',
            'focus': 'Form/URL fuzzing, auth/session manipulation, and repeatable request testing.'
        },
        'nodegoat': {
            'mode': 'burp-http',
            'headline': 'Burp workflow for NodeGoat',
            'tool': 'Burp Suite Community',
            'focus': 'JWT/session behaviors, parameter validation bypass, and business logic tampering.'
        },
        'railsgoat': {
            'mode': 'burp-http',
            'headline': 'Burp workflow for RailsGoat',
            'tool': 'Burp Suite Community',
            'focus': 'Rails controller param mutation, auth/session flow abuse, and replay tests.'
        },
        'dvga': {
            'mode': 'graphql',
            'headline': 'GraphQL testing workflow (DVGA)',
            'tool': 'Burp Suite + GraphQL-aware request crafting',
            'focus': 'Query/mutation tampering, introspection checks, and token/role bypass attempts.'
        },
        'crapi': {
            'mode': 'api-http',
            'headline': 'API testing workflow (crAPI)',
            'tool': 'Burp Suite + API client (optional)',
            'focus': 'Endpoint enumeration, auth token abuse, object-level authorization checks.'
        },
        'vampi': {
            'mode': 'api-http',
            'headline': 'API testing workflow (VAmPI)',
            'tool': 'Burp Suite + API client (optional)',
            'focus': 'Parameter tampering, auth checks, and response-driven endpoint exploration.'
        },
        'dvws': {
            'mode': 'api-http',
            'headline': 'API testing workflow (DVWS)',
            'tool': 'Burp Suite + API client (optional)',
            'focus': 'Web service input mutation and authentication/authorization edge-case testing.'
        },
        'security-shepherd': {
            'mode': 'burp-http',
            'headline': 'Burp workflow for Security Shepherd',
            'tool': 'Burp Suite Community',
            'focus': 'CTF request manipulation across challenge modules.'
        },
        'juice-shop-ctf': {
            'mode': 'burp-http',
            'headline': 'Burp workflow for Juice Shop CTF',
            'tool': 'Burp Suite Community',
            'focus': 'Challenge-oriented tampering: auth, basket/order flows, and replay-based checks.'
        },
        'altoro': {
            'mode': 'burp-http',
            'headline': 'Burp workflow for Altoro',
            'tool': 'Burp Suite Community',
            'focus': 'Business-logic and session abuse through modified requests.'
        },
        'kubernetes-goat': {
            'mode': 'k8s',
            'headline': 'Kubernetes workflow (Kubernetes Goat)',
            'tool': 'kubectl + kube security tooling',
            'focus': 'Cluster object review, RBAC/misconfig analysis, and workload security checks.'
        },
        'kubehunter': {
            'mode': 'k8s',
            'headline': 'Kubernetes workflow (KubeHunter)',
            'tool': 'kube-hunter + kubectl',
            'focus': 'Cluster attack-surface discovery and validation of findings.'
        },
        'redis': {
            'mode': 'service-redis',
            'headline': 'Redis service workflow',
            'tool': 'redis-cli / netcat',
            'focus': 'Unauthenticated access, dangerous commands, and keyspace inspection.'
        },
        'ftp': {
            'mode': 'service-ftp',
            'headline': 'FTP service workflow',
            'tool': 'ftp/lftp/nmap',
            'focus': 'Anonymous login, weak credential checks, and file permission exposure.'
        },
        'ssh': {
            'mode': 'service-ssh',
            'headline': 'SSH service workflow',
            'tool': 'ssh + nmap',
            'focus': 'Banner/auth surface checks, weak credential policy testing, and hardening review.'
        }
    }

    profile = profiles.get(lab_type, {
        'mode': 'generic-http',
        'headline': 'Generic lab traffic workflow',
        'tool': 'Burp Suite for HTTP labs or protocol-native tooling for service labs',
        'focus': 'Inspect and manipulate protocol traffic specific to the selected target.'
    })

    mode = profile['mode']
    if mode in {'burp-http', 'api-http', 'graphql', 'generic-http'}:
        steps = [
            'Start Burp Suite and open a Temporary Project.',
            'Proxy listener must be 127.0.0.1:8080.',
            f'Open target URL: {access_url}' if access_url else 'Open your target lab URL.',
            'Turn Intercept on, capture request, modify params/headers/cookies, then Forward or send to Repeater.'
        ]
    elif mode == 'k8s':
        steps = [
            f'Use the exposed endpoint/port ({port}) only as entry point if needed; Burp is generally not primary here.',
            'Use kubectl to inspect namespaces, pods, services, roles, and bindings.',
            'Run kube-focused checks (for example kube-hunter workflows) and validate findings manually.',
            'Document misconfigurations and remediation steps.'
        ]
    elif mode == 'docker':
        steps = [
            'Inspect running container and image metadata with Docker CLI.',
            'Check capabilities, mounts, privileged mode, exposed sockets/ports, and env vars.',
            'Validate runtime escape/misconfiguration opportunities in a controlled way.',
            'Record hardening improvements.'
        ]
    elif mode == 'service-redis':
        steps = [
            f'Connect to Redis target on {port} using redis-cli or netcat.',
            'Test authentication requirements and accessible commands.',
            'Review keyspace exposure and risky operations (for example config/flush behaviors).',
            'Burp is not needed for this non-HTTP protocol.'
        ]
    elif mode == 'service-ftp':
        steps = [
            f'Connect to FTP target on {port} using ftp/lftp.',
            'Test anonymous login and weak credential scenarios.',
            'Enumerate accessible files/directories and write permissions.',
            'Burp is not needed for this non-HTTP protocol.'
        ]
    else:  # service-ssh and fallback service-like handling
        steps = [
            f'Connect to SSH target on {port} with ssh client tooling.',
            'Review banners, auth methods, and account hardening posture.',
            'Validate weak auth or misconfiguration scenarios in a safe test context.',
            'Burp is not needed for this non-HTTP protocol.'
        ]

    profile['steps'] = steps
    profile['target'] = access_url if access_url else (f'127.0.0.1:{port}' if port else 'n/a')
    profile['use_burp'] = mode in {'burp-http', 'api-http', 'graphql', 'generic-http'}
    return profile

def get_user_container_record(conn, user_id, lab_id=None):
    if lab_id:
        return conn.execute('SELECT * FROM containers WHERE id = ? AND user_id = ?', (lab_id, user_id)).fetchone()
    return conn.execute('SELECT * FROM containers WHERE user_id = ? ORDER BY id DESC LIMIT 1', (user_id,)).fetchone()

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def log_event(conn, event_type, user_id=None, target_user_id=None, details=None):
    details_json = json.dumps(details or {}, sort_keys=True)
    conn.execute(
        '''INSERT INTO event_log (event_type, user_id, target_user_id, source_ip, details_json)
           VALUES (?, ?, ?, ?, ?)''',
        (event_type, user_id, target_user_id, request.remote_addr if request else None, details_json)
    )

def get_user_role(user_id):
    conn = get_db_connection()
    row = conn.execute('SELECT role FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    return (row['role'] if row and row['role'] else 'student')

def current_user_role():
    if 'user_id' not in session:
        return 'student'
    if session.get('role'):
        return session.get('role')
    role = get_user_role(session['user_id'])
    session['role'] = role
    return role

def has_admin_user(conn):
    row = conn.execute("SELECT COUNT(*) AS c FROM users WHERE role = 'admin'").fetchone()
    return (row['c'] if row else 0) > 0

def require_roles(*roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            if current_user_role() not in roles:
                flash('Insufficient permissions for this action.', 'danger')
                return redirect(url_for('dashboard'))
            return fn(*args, **kwargs)
        return wrapper
    return decorator

def get_user_org_id(conn, user_id):
    row = conn.execute('SELECT organization_id FROM users WHERE id = ?', (user_id,)).fetchone()
    return row['organization_id'] if row and row['organization_id'] else 1

def can_user_launch_lab(conn, user_id):
    org_id = get_user_org_id(conn, user_id)
    org_budget = conn.execute('SELECT max_active_labs FROM organization_budgets WHERE organization_id = ?', (org_id,)).fetchone()
    if org_budget:
        current_org_active = conn.execute(
            '''SELECT COUNT(*) AS c
               FROM containers c
               JOIN users u ON u.id = c.user_id
               WHERE u.organization_id = ? AND c.status = 'running' ''',
            (org_id,)
        ).fetchone()['c']
        if current_org_active >= org_budget['max_active_labs']:
            return False, 'Organization lab budget reached. Ask an instructor/admin to raise the quota.'

    teams = conn.execute('SELECT team_id FROM team_memberships WHERE user_id = ?', (user_id,)).fetchall()
    for t in teams:
        team_quota = conn.execute('SELECT max_active_labs FROM teams WHERE id = ?', (t['team_id'],)).fetchone()
        if not team_quota:
            continue
        team_active = conn.execute(
            '''SELECT COUNT(*) AS c
               FROM containers c
               JOIN team_memberships tm ON tm.user_id = c.user_id
               WHERE tm.team_id = ? AND c.status = 'running' ''',
            (t['team_id'],)
        ).fetchone()['c']
        if team_active >= team_quota['max_active_labs']:
            return False, f"Team quota reached (team_id={t['team_id']})."

    return True, None

def get_catalog_labs(conn):
    rows = conn.execute('''
        SELECT slug, name, description, image, internal_port, entry_path, mem_limit,
               needs_volume, volume_path, version, tags_json, difficulty, learning_path,
               required_score, prerequisite_labs_json
        FROM lab_catalog
        WHERE is_active = 1
        ORDER BY learning_path, difficulty, name
    ''').fetchall()

    allowed_slugs = set(LAB_CONFIGS.keys())
    labs = {}
    for r in rows:
        if r['slug'] not in allowed_slugs:
            continue
        labs[r['slug']] = {
            'name': r['name'],
            'description': r['description'],
            'image': r['image'],
            'internal_port': r['internal_port'],
            'entry_path': r['entry_path'] or '',
            'mem_limit': r['mem_limit'],
            'needs_volume': bool(r['needs_volume']),
            'volume_path': r['volume_path'] or '',
            'version': r['version'] or '1.0.0',
            'tags': json.loads(r['tags_json'] or '[]'),
            'difficulty': r['difficulty'] or 'medium',
            'learning_path': r['learning_path'] or 'core',
            'required_score': r['required_score'] or 0,
            'prerequisite_labs': json.loads(r['prerequisite_labs_json'] or '[]')
        }
    return labs

def get_user_learning_paths(conn, user_id):
    rows = conn.execute(
        '''SELECT DISTINCT tlp.learning_path
           FROM team_learning_paths tlp
           JOIN team_memberships tm ON tm.team_id = tlp.team_id
           WHERE tm.user_id = ?''',
        (user_id,)
    ).fetchall()
    return [r['learning_path'] for r in rows if r['learning_path']]

def get_filtered_catalog_labs(conn, user_id, role):
    labs = get_catalog_labs(conn)
    if role in {'admin', 'instructor'}:
        return labs

    allowed_paths = set(get_user_learning_paths(conn, user_id))
    if not allowed_paths:
        return labs

    filtered = {}
    for slug, lab in labs.items():
        if lab.get('learning_path') in allowed_paths:
            filtered[slug] = lab
    return filtered

def mark_active_labs_completed(conn, user_id, source_event='solve'):
    running_labs = conn.execute(
        "SELECT DISTINCT lab_type FROM containers WHERE user_id = ? AND status = 'running'",
        (user_id,)
    ).fetchall()
    for lab in running_labs:
        conn.execute(
            '''INSERT OR IGNORE INTO user_lab_completions (user_id, lab_slug, completion_source)
               VALUES (?, ?, ?)''',
            (user_id, lab['lab_type'], source_event)
        )

def evaluate_lab_unlock(conn, user_id, role, lab_slug, lab_cfg):
    if role in {'admin', 'instructor'}:
        return True, ''

    required_score = int(lab_cfg.get('required_score') or 0)
    prereq_labs = lab_cfg.get('prerequisite_labs') or []

    user_score_row = conn.execute('SELECT score FROM users WHERE id = ?', (user_id,)).fetchone()
    user_score = user_score_row['score'] if user_score_row else 0
    if user_score < required_score:
        return False, f"Requires score >= {required_score}."

    if prereq_labs:
        completed = {
            r['lab_slug']
            for r in conn.execute('SELECT lab_slug FROM user_lab_completions WHERE user_id = ?', (user_id,)).fetchall()
        }
        missing = [slug for slug in prereq_labs if slug not in completed]
        if missing:
            return False, f"Complete prerequisites first: {', '.join(missing)}"

    return True, ''

def parse_csv_values(raw):
    if not raw:
        return []
    values = [v.strip() for v in raw.split(',')]
    return [v for v in values if v]

def cleanup_snapshot_retention():
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row

    rows = conn.execute('SELECT user_id, snapshot_retention_count FROM user_settings').fetchall()
    retention_by_user = {r['user_id']: (r['snapshot_retention_count'] or 5) for r in rows}
    default_retention = 5

    client = get_client()

    user_ids = [r['user_id'] for r in conn.execute('SELECT DISTINCT user_id FROM lab_snapshots').fetchall()]
    for user_id in user_ids:
        keep = retention_by_user.get(user_id, default_retention)
        snaps = conn.execute(
            'SELECT id, image_tag FROM lab_snapshots WHERE user_id = ? ORDER BY id DESC',
            (user_id,)
        ).fetchall()
        stale = snaps[keep:]
        for s in stale:
            if client:
                try:
                    client.images.remove(s['image_tag'], force=True)
                except Exception:
                    pass
            conn.execute('DELETE FROM lab_snapshots WHERE id = ?', (s['id'],))

    conn.commit()
    conn.close()

def compute_stuck_students(conn, org_id):
    rows = conn.execute(
        '''SELECT u.id AS user_id, u.username,
                  COALESCE(MAX(CASE WHEN e.event_type = 'flag_submitted_accepted' THEN e.created_at END), '') AS last_solve,
                  COALESCE(SUM(CASE WHEN e.event_type IN ('lab_reset', 'force_reset')
                                    AND e.created_at >= datetime('now', '-60 minutes') THEN 1 ELSE 0 END), 0) AS resets_60m,
                  COALESCE(SUM(CASE WHEN e.event_type = 'lab_started'
                                    AND e.created_at >= datetime('now', '-60 minutes') THEN 1 ELSE 0 END), 0) AS starts_60m,
                  COALESCE(SUM(CASE WHEN c.status = 'running' THEN 1 ELSE 0 END), 0) AS running_labs
           FROM users u
           LEFT JOIN event_log e ON e.user_id = u.id
           LEFT JOIN containers c ON c.user_id = u.id
           WHERE u.organization_id = ?
           GROUP BY u.id, u.username
           ORDER BY u.username''',
        (org_id,)
    ).fetchall()

    signals = []
    for r in rows:
        # Heuristic: likely stuck if many resets recently, has active labs, and no recent accepted solve.
        no_recent_solve = not r['last_solve']
        if r['resets_60m'] >= 2 and r['running_labs'] > 0 and no_recent_solve:
            signals.append({
                'user_id': r['user_id'],
                'username': r['username'],
                'resets_60m': r['resets_60m'],
                'starts_60m': r['starts_60m'],
                'running_labs': r['running_labs'],
                'reason': 'Multiple resets with no accepted solve recorded'
            })
    return signals

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            score INTEGER DEFAULT 0
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS containers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            container_id TEXT NOT NULL,
            port INTEGER NOT NULL,
            status TEXT NOT NULL,
            lab_type TEXT NOT NULL DEFAULT 'juice-shop',
            network_name TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    try:
        cursor.execute("ALTER TABLE containers ADD COLUMN lab_type TEXT NOT NULL DEFAULT 'juice-shop'")
    except sqlite3.OperationalError:
        pass # Column likely exists already
    try:
        cursor.execute("ALTER TABLE containers ADD COLUMN network_name TEXT")
    except sqlite3.OperationalError:
        pass
    cursor.execute("UPDATE containers SET network_name = 'cyberlab-user-' || user_id WHERE network_name IS NULL OR network_name = ''")
        
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS flags (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            flag_value TEXT UNIQUE NOT NULL,
            points INTEGER NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS solved_flags (
            user_id INTEGER,
            flag_id INTEGER,
            PRIMARY KEY (user_id, flag_id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS organizations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS organization_budgets (
            organization_id INTEGER PRIMARY KEY,
            max_active_labs INTEGER NOT NULL DEFAULT 50,
            FOREIGN KEY (organization_id) REFERENCES organizations (id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS teams (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            max_active_labs INTEGER NOT NULL DEFAULT 10,
            UNIQUE (organization_id, name),
            FOREIGN KEY (organization_id) REFERENCES organizations (id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS team_memberships (
            user_id INTEGER NOT NULL,
            team_id INTEGER NOT NULL,
            role TEXT NOT NULL DEFAULT 'student',
            PRIMARY KEY (user_id, team_id),
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (team_id) REFERENCES teams (id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS team_invites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            team_id INTEGER NOT NULL,
            invitee_username TEXT NOT NULL,
            invite_code TEXT UNIQUE NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            created_by INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (team_id) REFERENCES teams (id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS password_reset_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            requested_password_hash TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            resolved_at TIMESTAMP,
            resolved_by INTEGER,
            admin_note TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (resolved_by) REFERENCES users (id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS team_learning_paths (
            team_id INTEGER NOT NULL,
            learning_path TEXT NOT NULL,
            PRIMARY KEY (team_id, learning_path),
            FOREIGN KEY (team_id) REFERENCES teams (id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS announcements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id INTEGER NOT NULL,
            team_id INTEGER,
            message TEXT NOT NULL,
            created_by INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (organization_id) REFERENCES organizations (id),
            FOREIGN KEY (team_id) REFERENCES teams (id),
            FOREIGN KEY (created_by) REFERENCES users (id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS event_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            event_type TEXT NOT NULL,
            user_id INTEGER,
            target_user_id INTEGER,
            source_ip TEXT,
            details_json TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (target_user_id) REFERENCES users (id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS webhook_replay_guard (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            replay_key TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS lab_catalog (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            slug TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            image TEXT NOT NULL,
            internal_port TEXT NOT NULL,
            entry_path TEXT DEFAULT '',
            mem_limit TEXT NOT NULL,
            needs_volume INTEGER NOT NULL DEFAULT 0,
            volume_path TEXT DEFAULT '',
            version TEXT NOT NULL DEFAULT '1.0.0',
            tags_json TEXT NOT NULL DEFAULT '[]',
            difficulty TEXT NOT NULL DEFAULT 'medium',
            learning_path TEXT NOT NULL DEFAULT 'core',
            required_score INTEGER NOT NULL DEFAULT 0,
            prerequisite_labs_json TEXT NOT NULL DEFAULT '[]',
            is_active INTEGER NOT NULL DEFAULT 1,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_lab_completions (
            user_id INTEGER NOT NULL,
            lab_slug TEXT NOT NULL,
            completion_source TEXT NOT NULL DEFAULT 'solve',
            completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (user_id, lab_slug),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS flag_lab_mappings (
            flag_id INTEGER NOT NULL,
            lab_slug TEXT NOT NULL,
            PRIMARY KEY (flag_id, lab_slug),
            FOREIGN KEY (flag_id) REFERENCES flags (id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS lab_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            container_record_id INTEGER,
            snapshot_name TEXT NOT NULL,
            image_tag TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (container_record_id) REFERENCES containers (id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_settings (
            user_id INTEGER PRIMARY KEY,
            snapshot_retention_count INTEGER NOT NULL DEFAULT 5,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    try:
        cursor.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'student'")
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN organization_id INTEGER")
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE lab_catalog ADD COLUMN required_score INTEGER NOT NULL DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE lab_catalog ADD COLUMN prerequisite_labs_json TEXT NOT NULL DEFAULT '[]'")
    except sqlite3.OperationalError:
        pass

    # Ensure default organization + budget.
    cursor.execute("INSERT OR IGNORE INTO organizations (id, name) VALUES (1, 'Default Org')")
    cursor.execute("INSERT OR IGNORE INTO organization_budgets (organization_id, max_active_labs) VALUES (1, 50)")

    # Backfill users into default org + student role if needed.
    cursor.execute("UPDATE users SET role = 'student' WHERE role IS NULL OR role = ''")
    cursor.execute("UPDATE users SET organization_id = 1 WHERE organization_id IS NULL")
    # Seed a dummy flag if table is empty
    count = cursor.execute('SELECT COUNT(*) FROM flags').fetchone()[0]
    if count == 0:
        cursor.execute("INSERT INTO flags (flag_value, points) VALUES ('FLAG{DVWA-MASTER-HACKER}', 50)")

    # Ensure built-in labs exist in catalog (adds missing rows, does not overwrite existing customizations).
    default_tags = {
        'juice-shop': ['web', 'api', 'auth', 'sqli', 'xss'],
        'dvwa': ['web', 'sqli', 'xss', 'csrf'],
        'bwapp': ['web', 'auth', 'ssrf', 'sqli'],
        'webgoat': ['web', 'api', 'auth', 'learning'],
        'mutillidae': ['web', 'xss', 'sqli'],
        'railsgoat': ['modern', 'web', 'rails'],
        'dvga': ['api', 'graphql'],
        'vampi': ['api', 'rest'],
        'juice-shop-ctf': ['logic', 'ctf', 'web'],
        'kubehunter': ['devops', 'kubernetes'],
        'redis': ['services', 'network'],
        'ftp': ['services', 'network'],
        'ssh': ['services', 'network']
    }
    default_difficulty = {
        'dvwa': 'easy',
        'vampi': 'easy',
        'juice-shop': 'medium',
        'bwapp': 'medium',
        'mutillidae': 'medium',
        'dvga': 'medium',
        'redis': 'medium',
        'ftp': 'medium',
        'ssh': 'medium',
        'railsgoat': 'hard',
        'webgoat': 'hard',
        'juice-shop-ctf': 'hard',
        'kubehunter': 'hard'
    }
    default_paths = {
        'juice-shop': 'web',
        'dvwa': 'web',
        'bwapp': 'web',
        'webgoat': 'web',
        'mutillidae': 'web',
        'railsgoat': 'modern',
        'dvga': 'modern',
        'vampi': 'api',
        'juice-shop-ctf': 'logic',
        'kubehunter': 'devops',
        'redis': 'services',
        'ftp': 'services',
        'ssh': 'services'
    }
    default_required_score = {
        'dvwa': 0,
        'juice-shop': 10,
        'bwapp': 20,
        'webgoat': 40,
        'mutillidae': 15,
        'railsgoat': 30,
        'dvga': 20,
        'vampi': 10,
        'juice-shop-ctf': 40,
        'kubehunter': 40,
        'redis': 15,
        'ftp': 15,
        'ssh': 15
    }
    default_prereqs = {
        'juice-shop': ['dvwa'],
        'bwapp': ['juice-shop'],
        'webgoat': ['bwapp'],
        'mutillidae': ['dvwa'],
        'railsgoat': ['juice-shop'],
        'dvga': ['juice-shop'],
        'vampi': ['dvwa'],
        'juice-shop-ctf': ['juice-shop'],
        'kubehunter': [],
        'redis': ['dvwa'],
        'ftp': ['dvwa'],
        'ssh': ['dvwa']
    }
    for slug, cfg in LAB_CONFIGS.items():
        cursor.execute(
            '''INSERT OR IGNORE INTO lab_catalog
               (slug, name, description, image, internal_port, entry_path, mem_limit, needs_volume,
                volume_path, version, tags_json, difficulty, learning_path, required_score, prerequisite_labs_json, is_active)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)''',
            (
                slug,
                cfg['name'],
                cfg['description'],
                cfg['image'],
                cfg['internal_port'],
                cfg.get('entry_path', ''),
                cfg['mem_limit'],
                1 if cfg.get('needs_volume') else 0,
                cfg.get('volume_path', ''),
                '1.0.0',
                json.dumps(default_tags.get(slug, ['web'])),
                default_difficulty.get(slug, 'medium'),
                default_paths.get(slug, 'core'),
                default_required_score.get(slug, 0),
                json.dumps(default_prereqs.get(slug, []))
            )
        )

    conn.commit()
    conn.close()

init_db()

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if not username or not password:
            flash("Username and password required.", "danger")
            return redirect(url_for('register'))
            
        password_hash = generate_password_hash(password)
        
        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (username, password_hash, role, organization_id) VALUES (?, ?, ?, ?)', 
                         (username, password_hash, 'student', 1))
            created_user = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
            if created_user:
                log_event(conn, 'user_registered', user_id=created_user['id'], details={'username': username})
            conn.commit()
            flash("Registration successful. Please login.", "success")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Username already exists.", "danger")
        finally:
            conn.close()
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role'] if 'role' in user.keys() else 'student'
            conn = get_db_connection()
            log_event(conn, 'user_login', user_id=user['id'], details={'username': user['username']})
            conn.commit()
            conn.close()
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials.", "danger")
            
    return render_template('login.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        new_password = request.form.get('new_password') or ''
        confirm_password = request.form.get('confirm_password') or ''

        if not username or not new_password:
            flash('Username and new password are required.', 'danger')
            return redirect(url_for('forgot_password'))
        if new_password != confirm_password:
            flash('Password confirmation does not match.', 'danger')
            return redirect(url_for('forgot_password'))
        if len(new_password) < 6:
            flash('Password must be at least 6 characters.', 'danger')
            return redirect(url_for('forgot_password'))

        conn = get_db_connection()
        user = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
        if user:
            conn.execute(
                '''INSERT INTO password_reset_requests (user_id, requested_password_hash, status)
                   VALUES (?, ?, 'pending')''',
                (user['id'], generate_password_hash(new_password))
            )
            log_event(conn, 'password_reset_requested', user_id=user['id'], details={'username': username})
            conn.commit()
        conn.close()

        flash('If the account exists, a password reset request was submitted for admin approval.', 'success')
        return redirect(url_for('login'))

    return render_template('forgot_password.html')

@app.route('/account/password', methods=['POST'])
def account_password_update():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    current_password = request.form.get('current_password') or ''
    new_password = request.form.get('new_password') or ''
    confirm_password = request.form.get('confirm_password') or ''

    if not current_password or not new_password:
        flash('Current and new password are required.', 'danger')
        return redirect(url_for('dashboard'))
    if new_password != confirm_password:
        flash('Password confirmation does not match.', 'danger')
        return redirect(url_for('dashboard'))
    if len(new_password) < 6:
        flash('New password must be at least 6 characters.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    if not user or not check_password_hash(user['password_hash'], current_password):
        conn.close()
        flash('Current password is incorrect.', 'danger')
        return redirect(url_for('dashboard'))

    conn.execute('UPDATE users SET password_hash = ? WHERE id = ?', (generate_password_hash(new_password), session['user_id']))
    log_event(conn, 'password_changed_self_service', user_id=session['user_id'], details={'username': session.get('username')})
    conn.commit()
    conn.close()
    flash('Password updated successfully.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/admin/bootstrap', methods=['GET', 'POST'])
def admin_bootstrap():
    conn = get_db_connection()
    already_bootstrapped = has_admin_user(conn)
    conn.close()

    if request.method == 'POST':
        if already_bootstrapped:
            flash('Admin already exists. Bootstrap is disabled.', 'warning')
            return redirect(url_for('login'))

        username = (request.form.get('username') or '').strip()
        bootstrap_key = (request.form.get('bootstrap_key') or '').strip()
        expected_key = os.environ.get('CYBERLAB_BOOTSTRAP_KEY', '').strip()

        if not username:
            flash('Username is required.', 'danger')
            return redirect(url_for('admin_bootstrap'))
        if not expected_key:
            flash('Server bootstrap key is not configured (CYBERLAB_BOOTSTRAP_KEY).', 'danger')
            return redirect(url_for('admin_bootstrap'))
        if bootstrap_key != expected_key:
            flash('Invalid bootstrap key.', 'danger')
            return redirect(url_for('admin_bootstrap'))

        conn = get_db_connection()
        user = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
        if not user:
            conn.close()
            flash('User not found.', 'danger')
            return redirect(url_for('admin_bootstrap'))

        conn.execute("UPDATE users SET role = 'admin' WHERE id = ?", (user['id'],))
        log_event(conn, 'admin_bootstrap_completed', user_id=user['id'], details={'username': username})
        conn.commit()
        conn.close()
        flash(f'Bootstrap complete. {username} is now admin.', 'success')
        return redirect(url_for('login'))

    return render_template('admin_bootstrap.html', already_bootstrapped=already_bootstrapped)

@app.route('/logout')
def logout():
    if 'user_id' in session:
        conn = get_db_connection()
        log_event(conn, 'user_logout', user_id=session.get('user_id'), details={'username': session.get('username')})
        conn.commit()
        conn.close()
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    user_id = session['user_id']
    username = session['username']
    host = request.host.split(':')[0]
    
    conn = get_db_connection()
    container_records = conn.execute('SELECT * FROM containers WHERE user_id = ? ORDER BY id DESC', (user_id,)).fetchall()
    
    # Leaderboard Data
    leaderboard = conn.execute('SELECT username, score FROM users ORDER BY score DESC LIMIT 10').fetchall()
    role = current_user_role()
    labs = get_filtered_catalog_labs(conn, user_id, role)
    if not labs:
        labs = LAB_CONFIGS

    lab_unlocks = {}
    if isinstance(labs, dict):
        for slug, lab_cfg in labs.items():
            unlocked, reason = evaluate_lab_unlock(conn, user_id, role, slug, lab_cfg)
            lab_unlocks[slug] = {'unlocked': unlocked, 'reason': reason}

    org_id = get_user_org_id(conn, user_id)
    team_ids = [r['team_id'] for r in conn.execute('SELECT team_id FROM team_memberships WHERE user_id = ?', (user_id,)).fetchall()]
    announcements = conn.execute(
        '''SELECT a.*, u.username AS created_by_username
           FROM announcements a
           LEFT JOIN users u ON u.id = a.created_by
           WHERE a.organization_id = ?
             AND (a.team_id IS NULL OR a.team_id IN ({placeholders}))
           ORDER BY a.created_at DESC
           LIMIT 10'''.format(placeholders=','.join(['?'] * max(1, len(team_ids)))),
        ([org_id] + (team_ids if team_ids else [-1]))
    ).fetchall()

    pending_invites = conn.execute(
        '''SELECT ti.id, ti.invitee_username, ti.invite_code, ti.created_at, t.name AS team_name
           FROM team_invites ti
           JOIN teams t ON t.id = ti.team_id
           WHERE ti.status = 'pending' AND ti.invitee_username = ?
           ORDER BY ti.created_at DESC''',
        (username,)
    ).fetchall()

    team_scores = conn.execute(
        '''SELECT t.id, t.name, COALESCE(SUM(u.score), 0) AS total_score
           FROM teams t
           LEFT JOIN team_memberships tm ON tm.team_id = t.id
           LEFT JOIN users u ON u.id = tm.user_id
           WHERE t.organization_id = ?
           GROUP BY t.id, t.name
           ORDER BY total_score DESC, t.name ASC''',
        (org_id,)
    ).fetchall()

    snapshots = conn.execute(
        '''SELECT id, snapshot_name, image_tag, created_at
           FROM lab_snapshots
           WHERE user_id = ?
           ORDER BY id DESC
           LIMIT 10''',
        (user_id,)
    ).fetchall()
    retention_row = conn.execute('SELECT snapshot_retention_count FROM user_settings WHERE user_id = ?', (user_id,)).fetchone()
    snapshot_retention_count = retention_row['snapshot_retention_count'] if retention_row else 5

    containers = []
    stale_ids = []

    for record in container_records:
        view = build_container_view(record, host)
        if view['status'] == 'not_found':
            stale_ids.append(record['id'])
            continue

        if view['status'] != record['status']:
            conn.execute('UPDATE containers SET status = ? WHERE id = ?', (view['status'], record['id']))

        containers.append(view)

    if stale_ids:
        conn.executemany('DELETE FROM containers WHERE id = ?', [(row_id,) for row_id in stale_ids])
        flash("Stale lab records were cleaned up automatically.", "warning")

    conn.commit()
    conn.close()

    primary_container = None
    for item in containers:
        if item['status'] == 'running' and item['is_ready']:
            primary_container = item
            break
    if not primary_container and containers:
        primary_container = containers[0]

    return render_template(
        'dashboard.html',
        username=username,
        containers=containers,
        primary_container=primary_container,
        leaderboard=leaderboard,
        labs=labs,
        announcements=announcements,
        role=role,
        pending_invites=pending_invites,
        team_scores=team_scores,
        snapshots=snapshots,
        snapshot_retention_count=snapshot_retention_count,
        lab_unlocks=lab_unlocks
    )

@app.route('/webhook/<int:user_id>', methods=['POST', 'PUT'])
def webhook(user_id):
    # Depending on how Juice Shop sends the CTF webhook, it might be POST or PUT
    data = request.json or {}

    conn = get_db_connection()

    replay_source = json.dumps(data, sort_keys=True)
    replay_key = request.headers.get('X-Event-ID') or hashlib.sha256(f"{user_id}:{replay_source}".encode()).hexdigest()

    # Anti-cheat 1: replay protection
    existing_key = conn.execute('SELECT id FROM webhook_replay_guard WHERE replay_key = ?', (replay_key,)).fetchone()
    if existing_key:
        log_event(conn, 'webhook_duplicate_rejected', user_id=user_id, details={'replay_key': replay_key})
        conn.commit()
        conn.close()
        return {'status': 'duplicate_rejected'}, 200

    # Anti-cheat 2: basic rate limit (max 30 webhook solves in 5 minutes)
    recent_count = conn.execute(
        """SELECT COUNT(*) AS c
           FROM event_log
           WHERE user_id = ?
             AND event_type = 'webhook_solve_accepted'
             AND created_at >= datetime('now', '-5 minutes')""",
        (user_id,)
    ).fetchone()['c']

    if recent_count >= 30:
        log_event(conn, 'webhook_rate_limited', user_id=user_id, details={'count_5m': recent_count})
        conn.commit()
        conn.close()
        return {'status': 'rate_limited'}, 429

    conn.execute('INSERT INTO webhook_replay_guard (user_id, replay_key) VALUES (?, ?)', (user_id, replay_key))
    conn.execute('UPDATE users SET score = score + 10 WHERE id = ?', (user_id,))
    mark_active_labs_completed(conn, user_id, source_event='webhook')
    log_event(conn, 'webhook_solve_accepted', user_id=user_id, details={'points_awarded': 10, 'payload': data})
    conn.commit()
    conn.close()
    
    return {'status': 'success'}, 200

@app.route('/start_lab', methods=['POST'])
def start_lab():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    user_id = session['user_id']
    lab_type = request.form.get('lab_type', 'juice-shop')
    
    conn = get_db_connection()
    allowed, reason = can_user_launch_lab(conn, user_id)
    if not allowed:
        flash(reason, 'danger')
        conn.close()
        return redirect(url_for('dashboard'))

    catalog_labs = get_catalog_labs(conn)
    if catalog_labs and lab_type not in catalog_labs:
        flash('Unknown lab type selected from catalog.', 'danger')
        conn.close()
        return redirect(url_for('dashboard'))

    selected_cfg = catalog_labs.get(lab_type) if catalog_labs else LAB_CONFIGS.get(lab_type, {})
    unlocked, reason = evaluate_lab_unlock(conn, user_id, current_user_role(), lab_type, selected_cfg or {})
    if not unlocked:
        flash(f'Lab locked: {reason}', 'warning')
        conn.close()
        return redirect(url_for('dashboard'))
            
    port = get_next_available_port(conn, start_port=3001)
        
    try:
        max_retries = 5
        container_id = None
        last_error = None

        for _ in range(max_retries):
            try:
                container_id = start_container(port, user_id, lab_type)
                break
            except Exception as e:
                last_error = e
                if 'port is already allocated' in str(e).lower():
                    port = get_next_available_port(conn, start_port=port + 1)
                    continue
                raise

        if not container_id:
            raise last_error or Exception('Unable to allocate a free port for lab startup.')

        network_name = get_lab_network_name(user_id)
        conn.execute('INSERT INTO containers (user_id, container_id, port, status, lab_type, network_name) VALUES (?, ?, ?, ?, ?, ?)',
                 (user_id, container_id, port, 'running', lab_type, network_name))
        log_event(conn, 'lab_started', user_id=user_id, details={'lab_type': lab_type, 'port': port, 'container_id': container_id, 'network_name': network_name})
        conn.commit()
        flash(f"New lab started on port {port}. It may take a moment to become fully accessible.", "success")
    except Exception as e:
        flash(f"Failed to start lab: {str(e)}", "danger")
    finally:
        conn.close()
        
    return redirect(url_for('dashboard'))

@app.route('/stop_lab', methods=['POST'])
def stop_lab():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    user_id = session['user_id']
    lab_id = request.form.get('lab_id', type=int)
    
    conn = get_db_connection()
    existing = get_user_container_record(conn, user_id, lab_id)
    
    if existing:
        try:
            stop_container(existing['container_id'])
            conn.execute('UPDATE containers SET status = ? WHERE id = ?', ('exited', existing['id']))
            log_event(conn, 'lab_stopped', user_id=user_id, details={'lab_id': existing['id'], 'port': existing['port'], 'container_id': existing['container_id']})
            conn.commit()
            flash(f"Lab on port {existing['port']} stopped.", "success")
        except Exception as e:
            flash(f"Failed to stop lab: {str(e)}", "danger")
    else:
        flash("Selected lab was not found.", "warning")
    
    conn.close()
    return redirect(url_for('dashboard'))

@app.route('/reset_lab', methods=['POST'])
def reset_lab():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    user_id = session['user_id']
    lab_id = request.form.get('lab_id', type=int)
    
    conn = get_db_connection()
    existing = get_user_container_record(conn, user_id, lab_id)
    
    if existing:
        old_container_id = existing['container_id']
        port = existing['port']
        
        try:
            remove_container(old_container_id)
            if not is_port_available(port):
                port = get_next_available_port(conn, start_port=port + 1)
            new_container_id = start_container(port, user_id, dict(existing).get('lab_type', 'juice-shop'))
            network_name = get_lab_network_name(user_id)
            
            conn.execute('UPDATE containers SET container_id = ?, status = ?, port = ?, network_name = ? WHERE id = ?', 
                         (new_container_id, 'running', port, network_name, existing['id']))
            log_event(conn, 'lab_reset', user_id=user_id, details={'lab_id': existing['id'], 'old_container_id': old_container_id, 'new_container_id': new_container_id, 'port': port, 'network_name': network_name})
            conn.commit()
            flash(f"Lab reset successfully on port {port}.", "success")
            
        except Exception as e:
            flash(f"Failed to reset lab: {str(e)}", "danger")
    else:
        flash("Selected lab was not found.", "warning")
            
    conn.close()
    return redirect(url_for('dashboard'))

@app.route('/destroy_lab', methods=['POST'])
def destroy_lab():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    user_id = session['user_id']
    lab_id = request.form.get('lab_id', type=int)
    
    conn = get_db_connection()
    existing = get_user_container_record(conn, user_id, lab_id)
    
    if existing:
        old_container_id = existing['container_id']
        try:
            remove_container(old_container_id)
            conn.execute('DELETE FROM containers WHERE id = ? AND user_id = ?', (existing['id'], user_id))
            network_removed = prune_user_network_if_unused(user_id)
            log_event(conn, 'lab_destroyed', user_id=user_id, details={'lab_id': existing['id'], 'port': existing['port'], 'container_id': old_container_id, 'network_removed': network_removed})
            conn.commit()
            flash(f"Lab on port {existing['port']} destroyed.", "success")
        except Exception as e:
            flash(f"Failed to destroy lab: {str(e)}", "danger")
    else:
        flash("Selected lab was not found.", "warning")
            
    conn.close()
    return redirect(url_for('dashboard'))

@app.route('/checkpoint/save', methods=['POST'])
def save_checkpoint():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    lab_id = request.form.get('lab_id', type=int)
    snapshot_name = (request.form.get('snapshot_name') or '').strip()
    if not snapshot_name:
        snapshot_name = f"checkpoint-{int(time.time())}"

    conn = get_db_connection()
    lab = get_user_container_record(conn, user_id, lab_id)
    if not lab:
        conn.close()
        flash('Lab instance not found for checkpoint.', 'warning')
        return redirect(url_for('dashboard'))

    try:
        client = get_client()
        if not client:
            raise Exception('Docker is not available.')

        image_tag = f"cyberlab-checkpoint-{user_id}-{lab['id']}-{int(time.time())}"
        container = client.containers.get(lab['container_id'])
        container.commit(repository=image_tag)

        conn.execute(
            'INSERT INTO lab_snapshots (user_id, container_record_id, snapshot_name, image_tag) VALUES (?, ?, ?, ?)',
            (user_id, lab['id'], snapshot_name, image_tag)
        )
        log_event(conn, 'checkpoint_saved', user_id=user_id, details={'lab_id': lab['id'], 'snapshot_name': snapshot_name, 'image_tag': image_tag})
        conn.commit()
        flash(f'Checkpoint saved: {snapshot_name}', 'success')
    except Exception as e:
        flash(f'Failed to save checkpoint: {e}', 'danger')
    finally:
        conn.close()

    return redirect(url_for('dashboard'))

@app.route('/checkpoint/restore', methods=['POST'])
def restore_checkpoint():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    lab_id = request.form.get('lab_id', type=int)
    snapshot_id = request.form.get('snapshot_id', type=int)

    conn = get_db_connection()
    lab = get_user_container_record(conn, user_id, lab_id)
    snapshot = conn.execute('SELECT * FROM lab_snapshots WHERE id = ? AND user_id = ?', (snapshot_id, user_id)).fetchone()

    if not lab or not snapshot:
        conn.close()
        flash('Checkpoint restore target not found.', 'warning')
        return redirect(url_for('dashboard'))

    try:
        client = get_client()
        if not client:
            raise Exception('Docker is not available.')

        old_container_id = lab['container_id']
        remove_container(old_container_id)

        run_kwargs = {
            'image': snapshot['image_tag'],
            'detach': True,
            'ports': {LAB_CONFIGS.get(lab['lab_type'], {}).get('internal_port', '80/tcp'): lab['port']},
            'labels': {
                'app': f"{lab['lab_type']}-lab",
                'user_id': str(user_id),
                'managed_by': 'cyberlab',
                'network_name': get_lab_network_name(user_id)
            },
            'network': ensure_lab_network(user_id).name,
            'mem_limit': LAB_CONFIGS.get(lab['lab_type'], {}).get('mem_limit', '512m')
        }
        container = client.containers.run(**run_kwargs)

        conn.execute('UPDATE containers SET container_id = ?, status = ?, network_name = ? WHERE id = ?', (container.id, 'running', get_lab_network_name(user_id), lab['id']))
        log_event(conn, 'checkpoint_restored', user_id=user_id, details={'lab_id': lab['id'], 'snapshot_id': snapshot_id, 'image_tag': snapshot['image_tag'], 'network_name': get_lab_network_name(user_id)})
        conn.commit()
        flash(f'Checkpoint restored: {snapshot["snapshot_name"]}', 'success')
    except Exception as e:
        flash(f'Failed to restore checkpoint: {e}', 'danger')
    finally:
        conn.close()

    return redirect(url_for('dashboard'))

@app.route('/checkpoint/settings', methods=['POST'])
def checkpoint_settings():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    retention = request.form.get('snapshot_retention_count', type=int)
    if retention is None or retention < 1:
        flash('Retention count must be at least 1.', 'danger')
        return redirect(url_for('dashboard'))

    retention = min(retention, 50)
    conn = get_db_connection()
    conn.execute(
        '''INSERT INTO user_settings (user_id, snapshot_retention_count)
           VALUES (?, ?)
           ON CONFLICT(user_id) DO UPDATE SET snapshot_retention_count = excluded.snapshot_retention_count''',
        (user_id, retention)
    )
    log_event(conn, 'checkpoint_retention_updated', user_id=user_id, details={'snapshot_retention_count': retention})
    conn.commit()
    conn.close()
    flash(f'Checkpoint retention updated to {retention}.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/port_cleaner')
def port_cleaner():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    host = request.host.split(':')[0]
    conn = get_db_connection()
    records = conn.execute('SELECT * FROM containers WHERE user_id = ? ORDER BY id DESC', (user_id,)).fetchall()

    ports = []
    stale_ids = []
    tracked_container_ids = set()

    for record in records:
        record_dict = dict(record)
        real_status = get_container_status(record_dict['container_id'])

        if real_status == 'not_found':
            stale_ids.append(record_dict['id'])
            continue

        lab_type = record_dict.get('lab_type', 'juice-shop')
        lab_conf = LAB_CONFIGS.get(lab_type, {})
        lab_path = lab_conf.get('entry_path', '')
        tracked_container_ids.add(record_dict['container_id'])
        ports.append({
            'id': record_dict['id'],
            'port': record_dict['port'],
            'container_id': record_dict['container_id'][:12],
            'container_id_full': record_dict['container_id'],
            'lab_type': lab_type,
            'lab_name': lab_conf.get('name', lab_type.upper()),
            'network_name': record_dict.get('network_name') or get_lab_network_name(user_id),
            'db_status': record_dict['status'],
            'docker_status': real_status,
            'is_listening': is_port_listening(record_dict['port']),
            'access_url': f"http://{host}:{record_dict['port']}{lab_path}"
        })

        if real_status != record_dict['status']:
            conn.execute('UPDATE containers SET status = ? WHERE id = ?', (real_status, record_dict['id']))

    if stale_ids:
        conn.executemany('DELETE FROM containers WHERE id = ?', [(row_id,) for row_id in stale_ids])

    # Include user-owned Docker containers that may not have DB rows (orphaned records)
    client = get_client()
    if client:
        docker_user_containers = client.containers.list(all=True, filters={"label": f"user_id={user_id}"})
        for docker_container in docker_user_containers:
            if docker_container.id in tracked_container_ids:
                continue

            labels = docker_container.labels or {}
            app_label = labels.get('app', '')
            lab_type = app_label[:-4] if app_label.endswith('-lab') else 'unknown'
            lab_conf = LAB_CONFIGS.get(lab_type, {})
            lab_path = lab_conf.get('entry_path', '')

            bound_port = None
            ports_map = (docker_container.attrs.get('NetworkSettings', {}) or {}).get('Ports', {}) or {}
            for _, bindings in ports_map.items():
                if bindings and isinstance(bindings, list) and bindings[0].get('HostPort'):
                    try:
                        bound_port = int(bindings[0]['HostPort'])
                        break
                    except (ValueError, TypeError):
                        bound_port = None

            access_url = f"http://{host}:{bound_port}{lab_path}" if bound_port else None
            networks_map = (docker_container.attrs.get('NetworkSettings', {}) or {}).get('Networks', {}) or {}
            network_name = next(iter(networks_map.keys()), get_lab_network_name(user_id))

            ports.append({
                'id': None,
                'port': bound_port,
                'container_id': docker_container.id[:12],
                'container_id_full': docker_container.id,
                'lab_type': lab_type,
                'lab_name': lab_conf.get('name', lab_type.upper()),
                'network_name': network_name,
                'db_status': 'missing_record',
                'docker_status': docker_container.status,
                'is_listening': is_port_listening(bound_port) if bound_port else False,
                'access_url': access_url
            })

    conn.commit()
    conn.close()

    return render_template('port_cleaner.html', ports=ports)

@app.route('/port_cleaner/clean_all', methods=['POST'])
def port_cleaner_clean_all():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db_connection()
    records = conn.execute('SELECT * FROM containers WHERE user_id = ?', (user_id,)).fetchall()

    removed_count = 0
    failed_count = 0
    removed_ids = set()

    for record in records:
        record_dict = dict(record)
        try:
            remove_container(record_dict['container_id'])
            removed_count += 1
            removed_ids.add(record_dict['container_id'])
        except Exception:
            failed_count += 1

    # Also cleanup user-labeled Docker containers that do not have DB rows.
    client = get_client()
    if client:
        docker_user_containers = client.containers.list(all=True, filters={"label": f"user_id={user_id}"})
        for docker_container in docker_user_containers:
            if docker_container.id in removed_ids:
                continue
            try:
                remove_container(docker_container.id)
                removed_count += 1
            except Exception:
                failed_count += 1

    conn.execute('DELETE FROM containers WHERE user_id = ?', (user_id,))
    network_removed = prune_user_network_if_unused(user_id)
    conn.commit()
    conn.close()

    if failed_count:
        conn = get_db_connection()
        log_event(conn, 'port_cleaner_clean_all_partial', user_id=user_id, details={'removed': removed_count, 'failed': failed_count, 'network_removed': network_removed})
        conn.commit()
        conn.close()
        flash(f"Port cleaner completed with warnings: {removed_count} container(s) removed, {failed_count} failed. Any stale records were cleaned.", "warning")
    else:
        conn = get_db_connection()
        log_event(conn, 'port_cleaner_clean_all', user_id=user_id, details={'removed': removed_count, 'network_removed': network_removed})
        conn.commit()
        conn.close()
        flash(f"Port cleaner complete: {removed_count} container(s) removed and your lab ports are now free.", "success")

    return redirect(url_for('port_cleaner'))

@app.route('/port_cleaner/action', methods=['POST'])
def port_cleaner_action():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    container_id = (request.form.get('container_id') or '').strip()
    action = (request.form.get('action') or '').strip().lower()

    if not container_id or action not in {'stop', 'resume', 'destroy'}:
        flash('Invalid port cleaner action.', 'danger')
        return redirect(url_for('port_cleaner'))

    conn = get_db_connection()
    row = conn.execute('SELECT * FROM containers WHERE user_id = ? AND container_id = ?', (user_id, container_id)).fetchone()

    owner_verified = row is not None
    if not owner_verified:
        client = get_client()
        if client:
            try:
                docker_container = client.containers.get(container_id)
                owner_verified = (docker_container.labels or {}).get('user_id') == str(user_id)
            except Exception:
                owner_verified = False

    if not owner_verified:
        conn.close()
        flash('Container not found for your account.', 'warning')
        return redirect(url_for('port_cleaner'))

    try:
        if action == 'stop':
            stop_container(container_id)
            if row:
                conn.execute('UPDATE containers SET status = ? WHERE id = ?', ('exited', row['id']))
            log_event(conn, 'port_cleaner_stop', user_id=user_id, details={'container_id': container_id})
            flash('Container stopped.', 'success')
        elif action == 'resume':
            resume_container(container_id)
            if row:
                conn.execute('UPDATE containers SET status = ? WHERE id = ?', ('running', row['id']))
            log_event(conn, 'port_cleaner_resume', user_id=user_id, details={'container_id': container_id})
            flash('Container resumed.', 'success')
        elif action == 'destroy':
            remove_container(container_id)
            if row:
                conn.execute('DELETE FROM containers WHERE id = ?', (row['id'],))
            network_removed = prune_user_network_if_unused(user_id)
            log_event(conn, 'port_cleaner_destroy', user_id=user_id, details={'container_id': container_id, 'network_removed': network_removed})
            flash('Container destroyed and port freed.', 'success')
    except Exception as e:
        flash(f'Failed to {action} container: {str(e)}', 'danger')

    conn.commit()
    conn.close()
    return redirect(url_for('port_cleaner'))

@app.route('/submit_flag', methods=['POST'])
def submit_flag():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    user_id = session['user_id']
    submitted_flag = request.form.get('flag', '').strip()
    
    conn = get_db_connection()
    flag_record = conn.execute('SELECT * FROM flags WHERE flag_value = ?', (submitted_flag,)).fetchone()
    
    if flag_record:
        flag_id = flag_record['id']
        points = flag_record['points']
        
        # Check if already solved
        solved = conn.execute('SELECT * FROM solved_flags WHERE user_id = ? AND flag_id = ?', (user_id, flag_id)).fetchone()
        if solved:
            log_event(conn, 'flag_duplicate_rejected', user_id=user_id, details={'flag_id': flag_id})
            flash("You have already claimed this flag!", "warning")
        else:
            conn.execute('INSERT INTO solved_flags (user_id, flag_id) VALUES (?, ?)', (user_id, flag_id))
            conn.execute('UPDATE users SET score = score + ? WHERE id = ?', (points, user_id))

            mapped_labs = conn.execute('SELECT lab_slug FROM flag_lab_mappings WHERE flag_id = ?', (flag_id,)).fetchall()
            if mapped_labs:
                for m in mapped_labs:
                    conn.execute(
                        '''INSERT OR IGNORE INTO user_lab_completions (user_id, lab_slug, completion_source)
                           VALUES (?, ?, ?)''',
                        (user_id, m['lab_slug'], 'manual_flag')
                    )
            else:
                # Fallback for backward compatibility if no explicit mapping exists.
                mark_active_labs_completed(conn, user_id, source_event='manual_flag')

            log_event(conn, 'flag_submitted_accepted', user_id=user_id, details={'flag_id': flag_id, 'points': points})
            conn.commit()
            flash(f"Flag Accepted! You earned {points} points.", "success")
    else:
        log_event(conn, 'flag_submitted_invalid', user_id=user_id, details={'flag': submitted_flag})
        conn.commit()
        flash("Invalid flag. Keep trying!", "danger")
        
    conn.close()
    return redirect(url_for('dashboard'))

@app.route('/proxy_guide')
def proxy_guide():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    user_id = session['user_id']
    lab_id = request.args.get('lab_id', type=int)
    host = request.host.split(':')[0]
    conn = get_db_connection()
    container_records = conn.execute('SELECT * FROM containers WHERE user_id = ? ORDER BY id DESC', (user_id,)).fetchall()
    conn.close()

    views = []
    selected_view = None
    for record in container_records:
        view = build_container_view(record, host)
        if view['status'] == 'not_found':
            continue
        views.append(view)

    if lab_id:
        for view in views:
            if view['id'] == lab_id:
                selected_view = view
                break

    if not selected_view and views:
        for view in views:
            if view['status'] == 'running':
                selected_view = view
                break
        if not selected_view:
            selected_view = views[0]

    guide = get_lab_proxy_profile(selected_view) if selected_view else None
    return render_template('proxy_guide.html', container=selected_view, containers=views, guide=guide)

@app.route('/terminal')
def terminal():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    user_id = session['user_id']
    lab_id = request.args.get('lab_id', type=int)
    host = request.host.split(':')[0]
    conn = get_db_connection()
    container_records = conn.execute('SELECT * FROM containers WHERE user_id = ? ORDER BY id DESC', (user_id,)).fetchall()
    conn.close()

    views = []
    selected_view = None
    for record in container_records:
        view = build_container_view(record, host)
        if view['status'] == 'not_found':
            continue
        views.append(view)

    if lab_id:
        for view in views:
            if view['id'] == lab_id:
                selected_view = view
                break

    if not selected_view and views:
        for view in views:
            if view['status'] == 'running' and view['access_mode'] != 'web':
                selected_view = view
                break
        if not selected_view and views:
            selected_view = views[0]

    return render_template('terminal.html', container=selected_view, containers=views)

@sock.route('/ws/terminal/<int:container_id>')
def terminal_socket(ws, container_id):
    if 'user_id' not in session:
        ws.close()
        return
    
    user_id = session['user_id']
    
    # Verify container belongs to user
    conn = get_db_connection()
    container_record = conn.execute(
        'SELECT * FROM containers WHERE id = ? AND user_id = ?',
        (container_id, user_id)
    ).fetchone()
    conn.close()
    
    if not container_record:
        ws.close()
        return
    
    try:
        client = get_client()
        container = client.containers.get(container_record['container_id'])
        
        while True:
            try:
                data = ws.receive(timeout=1)
                if data is None:
                    continue
                    
                # Execute command in container
                try:
                    result = container.exec_run(
                        data,
                        shell=True,
                        stdout=True,
                        stderr=True,
                        stdin=False
                    )
                    output = result.output.decode('utf-8', errors='ignore')
                    ws.send(output)
                except Exception as e:
                    ws.send(f"Error executing command: {str(e)}\n")
                    
            except Exception as e:
                # Timeout or connection error, continue
                continue
                
    except Exception as e:
        try:
            ws.send(f"Terminal error: {str(e)}\n")
        except:
            pass
    finally:
        try:
            ws.close()
        except:
            pass

@app.route('/catalog')
def catalog():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    role = current_user_role()
    labs = get_filtered_catalog_labs(conn, session['user_id'], role)
    unlocks = {}
    for slug, cfg in labs.items():
        unlocked, reason = evaluate_lab_unlock(conn, session['user_id'], role, slug, cfg)
        unlocks[slug] = {'unlocked': unlocked, 'reason': reason}
    conn.close()
    return render_template('catalog.html', labs=labs, role=role, lab_unlocks=unlocks)

@app.route('/content_pack/export')
@require_roles('admin', 'instructor')
def export_content_pack():
    conn = get_db_connection()
    labs = [dict(r) for r in conn.execute('SELECT * FROM lab_catalog ORDER BY slug').fetchall()]
    flags = [dict(r) for r in conn.execute('SELECT id, flag_value, points FROM flags ORDER BY id').fetchall()]
    mappings = [dict(r) for r in conn.execute('SELECT flag_id, lab_slug FROM flag_lab_mappings ORDER BY flag_id, lab_slug').fetchall()]
    payload = {
        'format_version': '1.0',
        'generated_at': int(time.time()),
        'labs': labs,
        'flags': flags,
        'flag_lab_mappings': mappings
    }
    log_event(conn, 'content_pack_exported', user_id=session['user_id'], details={'labs': len(labs), 'flags': len(flags), 'mappings': len(mappings)})
    conn.commit()
    conn.close()

    response = make_response(json.dumps(payload, indent=2))
    response.headers['Content-Type'] = 'application/json'
    response.headers['Content-Disposition'] = 'attachment; filename=cyberlab-content-pack.json'
    return response

@app.route('/content_pack/import', methods=['GET', 'POST'])
@require_roles('admin', 'instructor')
def import_content_pack():
    if request.method == 'POST':
        raw = request.form.get('pack_json', '').strip()
        if not raw:
            flash('Content pack JSON is required.', 'danger')
            return redirect(url_for('import_content_pack'))

        try:
            pack = json.loads(raw)
        except json.JSONDecodeError as e:
            flash(f'Invalid JSON: {e}', 'danger')
            return redirect(url_for('import_content_pack'))

        labs = pack.get('labs', [])
        flags = pack.get('flags', [])
        mappings = pack.get('flag_lab_mappings', [])
        conn = get_db_connection()
        imported_labs = 0
        imported_flags = 0
        imported_mappings = 0

        for lab in labs:
            slug = lab.get('slug')
            if not slug:
                continue
            conn.execute(
                '''INSERT INTO lab_catalog
                   (slug, name, description, image, internal_port, entry_path, mem_limit, needs_volume,
                    volume_path, version, tags_json, difficulty, learning_path, required_score, prerequisite_labs_json, is_active, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                   ON CONFLICT(slug) DO UPDATE SET
                       name=excluded.name,
                       description=excluded.description,
                       image=excluded.image,
                       internal_port=excluded.internal_port,
                       entry_path=excluded.entry_path,
                       mem_limit=excluded.mem_limit,
                       needs_volume=excluded.needs_volume,
                       volume_path=excluded.volume_path,
                       version=excluded.version,
                       tags_json=excluded.tags_json,
                       difficulty=excluded.difficulty,
                       learning_path=excluded.learning_path,
                      required_score=excluded.required_score,
                      prerequisite_labs_json=excluded.prerequisite_labs_json,
                       is_active=excluded.is_active,
                       updated_at=CURRENT_TIMESTAMP''',
                (
                    slug,
                    lab.get('name', slug),
                    lab.get('description', ''),
                    lab.get('image', ''),
                    lab.get('internal_port', '80/tcp'),
                    lab.get('entry_path', ''),
                    lab.get('mem_limit', '512m'),
                    1 if lab.get('needs_volume') else 0,
                    lab.get('volume_path', ''),
                    lab.get('version', '1.0.0'),
                    lab.get('tags_json', json.dumps(lab.get('tags', []))),
                    lab.get('difficulty', 'medium'),
                    lab.get('learning_path', 'core'),
                    int(lab.get('required_score', 0)),
                    lab.get('prerequisite_labs_json', json.dumps(lab.get('prerequisite_labs', []))),
                    1 if lab.get('is_active', 1) else 0
                )
            )
            imported_labs += 1

        for flag in flags:
            value = flag.get('flag_value')
            points = int(flag.get('points', 0))
            if not value:
                continue
            conn.execute(
                '''INSERT INTO flags (flag_value, points)
                   VALUES (?, ?)
                   ON CONFLICT(flag_value) DO UPDATE SET points = excluded.points''',
                (value, points)
            )
            imported_flags += 1

        for mapping in mappings:
            flag_id = mapping.get('flag_id')
            lab_slug = mapping.get('lab_slug')
            if not flag_id or not lab_slug:
                continue
            conn.execute(
                '''INSERT OR IGNORE INTO flag_lab_mappings (flag_id, lab_slug)
                   VALUES (?, ?)''',
                (flag_id, lab_slug)
            )
            imported_mappings += 1

        log_event(conn, 'content_pack_imported', user_id=session['user_id'], details={'labs': imported_labs, 'flags': imported_flags, 'mappings': imported_mappings})
        conn.commit()
        conn.close()
        flash(f'Content pack imported: {imported_labs} labs, {imported_flags} flags, {imported_mappings} mappings.', 'success')
        return redirect(url_for('catalog'))

    return render_template('content_pack_import.html')

@app.route('/instructor/activity')
@require_roles('admin', 'instructor')
def instructor_activity():
    conn = get_db_connection()
    org_id = get_user_org_id(conn, session['user_id'])
    team_filter = request.args.get('team_id', type=int)
    pending_password_requests = conn.execute(
        '''SELECT pr.id, pr.user_id, pr.status, pr.requested_at, u.username
           FROM password_reset_requests pr
           JOIN users u ON u.id = pr.user_id
           WHERE pr.status = 'pending' AND u.organization_id = ?
           ORDER BY pr.requested_at ASC''',
        (org_id,)
    ).fetchall()

    base_active_query = '''
        SELECT c.id, c.port, c.status, c.lab_type, c.container_id, u.id AS user_id, u.username
        FROM containers c
        JOIN users u ON u.id = c.user_id
        WHERE u.organization_id = ?
    '''
    params = [org_id]
    if team_filter:
        base_active_query += ' AND u.id IN (SELECT user_id FROM team_memberships WHERE team_id = ?)'
        params.append(team_filter)
    base_active_query += ' ORDER BY c.id DESC'

    active_rows = conn.execute(base_active_query, params).fetchall()

    event_type = (request.args.get('event_type') or '').strip()
    event_user = request.args.get('event_user', type=int)
    export_format = (request.args.get('export') or '').strip().lower()

    event_query = '''
        SELECT e.*, u.username
        FROM event_log e
        LEFT JOIN users u ON u.id = e.user_id
        WHERE 1=1
    '''
    event_params = []
    if event_type:
        event_query += ' AND e.event_type = ?'
        event_params.append(event_type)
    if event_user:
        event_query += ' AND e.user_id = ?'
        event_params.append(event_user)
    if team_filter:
        event_query += ' AND (e.user_id IN (SELECT user_id FROM team_memberships WHERE team_id = ?) OR e.user_id IS NULL)'
        event_params.append(team_filter)
    event_query += ' ORDER BY e.id DESC LIMIT 500'
    event_rows = conn.execute(event_query, event_params).fetchall()

    if export_format in {'json', 'csv'}:
        rows_dict = [dict(r) for r in event_rows]
        conn.close()
        if export_format == 'json':
            response = make_response(json.dumps(rows_dict, indent=2))
            response.headers['Content-Type'] = 'application/json'
            response.headers['Content-Disposition'] = 'attachment; filename=event-timeline.json'
            return response

        csv_buf = io.StringIO()
        writer = csv.DictWriter(csv_buf, fieldnames=['id', 'created_at', 'event_type', 'user_id', 'username', 'target_user_id', 'source_ip', 'details_json'])
        writer.writeheader()
        for row in rows_dict:
            writer.writerow({
                'id': row.get('id'),
                'created_at': row.get('created_at'),
                'event_type': row.get('event_type'),
                'user_id': row.get('user_id'),
                'username': row.get('username'),
                'target_user_id': row.get('target_user_id'),
                'source_ip': row.get('source_ip'),
                'details_json': row.get('details_json')
            })
        response = make_response(csv_buf.getvalue())
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = 'attachment; filename=event-timeline.csv'
        return response

    teams = conn.execute('SELECT id, name FROM teams WHERE organization_id = ? ORDER BY name', (org_id,)).fetchall()
    team_paths = conn.execute(
        '''SELECT t.id AS team_id, t.name AS team_name, tlp.learning_path
           FROM teams t
           LEFT JOIN team_learning_paths tlp ON tlp.team_id = t.id
           WHERE t.organization_id = ?
           ORDER BY t.name, tlp.learning_path''',
        (org_id,)
    ).fetchall()

    catalog_rules = conn.execute(
        '''SELECT slug, name, required_score, prerequisite_labs_json, learning_path, difficulty
           FROM lab_catalog
           ORDER BY learning_path, difficulty, name'''
    ).fetchall()

    flags = conn.execute('SELECT id, flag_value, points FROM flags ORDER BY id').fetchall()
    flag_mappings = conn.execute(
        '''SELECT fm.flag_id, f.flag_value, fm.lab_slug
           FROM flag_lab_mappings fm
           JOIN flags f ON f.id = fm.flag_id
           ORDER BY fm.flag_id, fm.lab_slug'''
    ).fetchall()

    # Basic resource monitoring for running tracked containers.
    monitor = []
    client = get_client()
    if client:
        for row in active_rows:
            if row['status'] != 'running':
                continue
            try:
                c = client.containers.get(row['container_id'])
                stats = c.stats(stream=False)
                mem_usage = stats.get('memory_stats', {}).get('usage', 0)
                mem_limit = stats.get('memory_stats', {}).get('limit', 1)
                cpu_delta = stats.get('cpu_stats', {}).get('cpu_usage', {}).get('total_usage', 0) - stats.get('precpu_stats', {}).get('cpu_usage', {}).get('total_usage', 0)
                sys_delta = stats.get('cpu_stats', {}).get('system_cpu_usage', 0) - stats.get('precpu_stats', {}).get('system_cpu_usage', 0)
                cpu_percent = (cpu_delta / sys_delta * 100.0) if sys_delta > 0 else 0.0
                monitor.append({
                    'container_short_id': row['container_id'][:12],
                    'username': row['username'],
                    'lab_type': row['lab_type'],
                    'port': row['port'],
                    'cpu_percent': round(cpu_percent, 2),
                    'mem_usage_mb': round(mem_usage / (1024 * 1024), 2),
                    'mem_limit_mb': round(mem_limit / (1024 * 1024), 2)
                })
            except Exception:
                continue

    users_for_filter = conn.execute('SELECT id, username FROM users WHERE organization_id = ? ORDER BY username', (org_id,)).fetchall()
    stuck_students = compute_stuck_students(conn, org_id)
    conn.close()
    return render_template(
        'instructor_activity.html',
        active_rows=active_rows,
        event_rows=event_rows,
        monitor=monitor,
        teams=teams,
        users_for_filter=users_for_filter,
        stuck_students=stuck_students,
        team_paths=team_paths,
        catalog_rules=catalog_rules,
        flags=flags,
        flag_mappings=flag_mappings,
        pending_password_requests=pending_password_requests,
        filter_event_type=event_type,
        filter_event_user=event_user,
        filter_team_id=team_filter
    )

@app.route('/instructor/announce', methods=['POST'])
@require_roles('admin', 'instructor')
def instructor_announce():
    message = (request.form.get('message') or '').strip()
    team_id = request.form.get('team_id', type=int)
    if not message:
        flash('Announcement message is required.', 'danger')
        return redirect(url_for('instructor_activity'))

    conn = get_db_connection()
    org_id = get_user_org_id(conn, session['user_id'])
    conn.execute(
        'INSERT INTO announcements (organization_id, team_id, message, created_by) VALUES (?, ?, ?, ?)',
        (org_id, team_id, message, session['user_id'])
    )
    log_event(conn, 'announcement_broadcast', user_id=session['user_id'], details={'team_id': team_id, 'message': message[:200]})
    conn.commit()
    conn.close()
    flash('Announcement broadcasted.', 'success')
    return redirect(url_for('instructor_activity'))

@app.route('/instructor/lab_action', methods=['POST'])
@require_roles('admin', 'instructor')
def instructor_lab_action():
    lab_id = request.form.get('lab_id', type=int)
    action = (request.form.get('action') or '').strip().lower()
    if not lab_id or action not in {'force_stop', 'force_reset', 'force_destroy'}:
        flash('Invalid instructor lab action.', 'danger')
        return redirect(url_for('instructor_activity'))

    conn = get_db_connection()
    row = conn.execute('SELECT * FROM containers WHERE id = ?', (lab_id,)).fetchone()
    if not row:
        conn.close()
        flash('Lab instance not found.', 'warning')
        return redirect(url_for('instructor_activity'))

    try:
        if action == 'force_stop':
            stop_container(row['container_id'])
            conn.execute('UPDATE containers SET status = ? WHERE id = ?', ('exited', row['id']))
        elif action == 'force_reset':
            old_id = row['container_id']
            remove_container(old_id)
            new_id = start_container(row['port'], row['user_id'], row['lab_type'])
            conn.execute('UPDATE containers SET container_id = ?, status = ? WHERE id = ?', (new_id, 'running', row['id']))
        elif action == 'force_destroy':
            remove_container(row['container_id'])
            conn.execute('DELETE FROM containers WHERE id = ?', (row['id'],))

        log_event(conn, action, user_id=session['user_id'], target_user_id=row['user_id'], details={'lab_id': lab_id, 'container_id': row['container_id'], 'port': row['port']})
        conn.commit()
        flash('Instructor action completed.', 'success')
    except Exception as e:
        flash(f'Instructor action failed: {e}', 'danger')
    finally:
        conn.close()

    return redirect(url_for('instructor_activity'))

@app.route('/instructor/invite', methods=['POST'])
@require_roles('admin', 'instructor')
def instructor_invite():
    team_id = request.form.get('team_id', type=int)
    invitee_username = (request.form.get('invitee_username') or '').strip()
    if not team_id or not invitee_username:
        flash('Team and invitee username are required.', 'danger')
        return redirect(url_for('instructor_activity'))

    invite_code = hashlib.sha256(f"{team_id}:{invitee_username}:{time.time()}".encode()).hexdigest()[:24]
    conn = get_db_connection()
    conn.execute(
        'INSERT INTO team_invites (team_id, invitee_username, invite_code, created_by) VALUES (?, ?, ?, ?)',
        (team_id, invitee_username, invite_code, session['user_id'])
    )
    log_event(conn, 'team_invite_created', user_id=session['user_id'], details={'team_id': team_id, 'invitee_username': invitee_username, 'invite_code': invite_code})
    conn.commit()
    conn.close()
    flash(f'Invite created for {invitee_username}: code {invite_code}', 'success')
    return redirect(url_for('instructor_activity'))

@app.route('/instructor/team_create', methods=['POST'])
@require_roles('admin', 'instructor')
def instructor_team_create():
    team_name = (request.form.get('team_name') or '').strip()
    max_active_labs = request.form.get('max_active_labs', type=int)

    if not team_name:
        flash('Team name is required.', 'danger')
        return redirect(url_for('instructor_activity'))
    if max_active_labs is None or max_active_labs < 1:
        flash('Team max active labs must be at least 1.', 'danger')
        return redirect(url_for('instructor_activity'))

    conn = get_db_connection()
    org_id = get_user_org_id(conn, session['user_id'])
    try:
        conn.execute(
            'INSERT INTO teams (organization_id, name, max_active_labs) VALUES (?, ?, ?)',
            (org_id, team_name, max_active_labs)
        )
        log_event(conn, 'team_created', user_id=session['user_id'], details={'team_name': team_name, 'max_active_labs': max_active_labs})
        conn.commit()
        flash(f'Team created: {team_name}', 'success')
    except sqlite3.IntegrityError:
        flash('Team name already exists in this organization.', 'warning')
    finally:
        conn.close()

    return redirect(url_for('instructor_activity'))

@app.route('/instructor/team_path', methods=['POST'])
@require_roles('admin', 'instructor')
def instructor_team_path():
    team_id = request.form.get('team_id', type=int)
    learning_path = (request.form.get('learning_path') or '').strip()
    action = (request.form.get('action') or 'add').strip().lower()

    if not team_id or not learning_path:
        flash('Team and learning path are required.', 'danger')
        return redirect(url_for('instructor_activity'))

    conn = get_db_connection()
    if action == 'remove':
        conn.execute('DELETE FROM team_learning_paths WHERE team_id = ? AND learning_path = ?', (team_id, learning_path))
        log_event(conn, 'team_learning_path_removed', user_id=session['user_id'], details={'team_id': team_id, 'learning_path': learning_path})
        flash('Learning path removed from team.', 'success')
    else:
        conn.execute('INSERT OR IGNORE INTO team_learning_paths (team_id, learning_path) VALUES (?, ?)', (team_id, learning_path))
        log_event(conn, 'team_learning_path_added', user_id=session['user_id'], details={'team_id': team_id, 'learning_path': learning_path})
        flash('Learning path assigned to team.', 'success')

    conn.commit()
    conn.close()
    return redirect(url_for('instructor_activity'))

@app.route('/instructor/catalog_rule', methods=['POST'])
@require_roles('admin', 'instructor')
def instructor_catalog_rule():
    lab_slug = (request.form.get('lab_slug') or '').strip()
    required_score = request.form.get('required_score', type=int)
    prerequisites_raw = (request.form.get('prerequisite_labs') or '').strip()

    if not lab_slug or required_score is None or required_score < 0:
        flash('Lab slug and a non-negative required score are required.', 'danger')
        return redirect(url_for('instructor_activity'))

    prereqs = parse_csv_values(prerequisites_raw)

    conn = get_db_connection()
    exists = conn.execute('SELECT id FROM lab_catalog WHERE slug = ?', (lab_slug,)).fetchone()
    if not exists:
        conn.close()
        flash('Lab slug not found in catalog.', 'warning')
        return redirect(url_for('instructor_activity'))

    conn.execute(
        'UPDATE lab_catalog SET required_score = ?, prerequisite_labs_json = ?, updated_at = CURRENT_TIMESTAMP WHERE slug = ?',
        (required_score, json.dumps(prereqs), lab_slug)
    )
    log_event(conn, 'catalog_rule_updated', user_id=session['user_id'], details={'lab_slug': lab_slug, 'required_score': required_score, 'prerequisites': prereqs})
    conn.commit()
    conn.close()
    flash('Catalog unlock rule updated.', 'success')
    return redirect(url_for('instructor_activity'))

@app.route('/instructor/flag_lab_mapping', methods=['POST'])
@require_roles('admin', 'instructor')
def instructor_flag_lab_mapping():
    flag_id = request.form.get('flag_id', type=int)
    lab_slug = (request.form.get('lab_slug') or '').strip()
    action = (request.form.get('action') or 'add').strip().lower()

    if not flag_id or not lab_slug:
        flash('Flag and lab slug are required.', 'danger')
        return redirect(url_for('instructor_activity'))

    conn = get_db_connection()
    if action == 'remove':
        conn.execute('DELETE FROM flag_lab_mappings WHERE flag_id = ? AND lab_slug = ?', (flag_id, lab_slug))
        log_event(conn, 'flag_lab_mapping_removed', user_id=session['user_id'], details={'flag_id': flag_id, 'lab_slug': lab_slug})
        flash('Flag mapping removed.', 'success')
    else:
        conn.execute('INSERT OR IGNORE INTO flag_lab_mappings (flag_id, lab_slug) VALUES (?, ?)', (flag_id, lab_slug))
        log_event(conn, 'flag_lab_mapping_added', user_id=session['user_id'], details={'flag_id': flag_id, 'lab_slug': lab_slug})
        flash('Flag mapping added.', 'success')

    conn.commit()
    conn.close()
    return redirect(url_for('instructor_activity'))

@app.route('/admin/password_reset/<int:request_id>/<action>', methods=['POST'])
@require_roles('admin')
def admin_password_reset_action(request_id, action):
    action = (action or '').strip().lower()
    if action not in {'approve', 'reject'}:
        flash('Invalid password reset action.', 'danger')
        return redirect(url_for('instructor_activity'))

    admin_note = (request.form.get('admin_note') or '').strip()
    conn = get_db_connection()
    request_row = conn.execute(
        '''SELECT pr.*, u.username
           FROM password_reset_requests pr
           JOIN users u ON u.id = pr.user_id
           WHERE pr.id = ?''',
        (request_id,)
    ).fetchone()

    if not request_row or request_row['status'] != 'pending':
        conn.close()
        flash('Password reset request not found or already processed.', 'warning')
        return redirect(url_for('instructor_activity'))

    if action == 'approve':
        conn.execute('UPDATE users SET password_hash = ? WHERE id = ?', (request_row['requested_password_hash'], request_row['user_id']))
        conn.execute(
            '''UPDATE password_reset_requests
               SET status = 'approved', resolved_at = CURRENT_TIMESTAMP, resolved_by = ?, admin_note = ?
               WHERE id = ?''',
            (session['user_id'], admin_note, request_id)
        )
        log_event(conn, 'password_reset_approved', user_id=session['user_id'], target_user_id=request_row['user_id'], details={'request_id': request_id, 'username': request_row['username']})
        flash(f'Password reset approved for {request_row["username"]}.', 'success')
    else:
        conn.execute(
            '''UPDATE password_reset_requests
               SET status = 'rejected', resolved_at = CURRENT_TIMESTAMP, resolved_by = ?, admin_note = ?
               WHERE id = ?''',
            (session['user_id'], admin_note, request_id)
        )
        log_event(conn, 'password_reset_rejected', user_id=session['user_id'], target_user_id=request_row['user_id'], details={'request_id': request_id, 'username': request_row['username']})
        flash(f'Password reset rejected for {request_row["username"]}.', 'warning')

    conn.commit()
    conn.close()
    return redirect(url_for('instructor_activity'))

@app.route('/invite/<invite_code>/accept', methods=['POST'])
def accept_team_invite(invite_code):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    invite = conn.execute('SELECT * FROM team_invites WHERE invite_code = ? AND status = ?', (invite_code, 'pending')).fetchone()
    if not invite:
        conn.close()
        flash('Invite not found or already used.', 'warning')
        return redirect(url_for('dashboard'))

    user = conn.execute('SELECT username FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    if not user or user['username'] != invite['invitee_username']:
        conn.close()
        flash('This invite is not for your account.', 'danger')
        return redirect(url_for('dashboard'))

    conn.execute('INSERT OR IGNORE INTO team_memberships (user_id, team_id, role) VALUES (?, ?, ?)', (session['user_id'], invite['team_id'], 'student'))
    conn.execute('UPDATE team_invites SET status = ? WHERE id = ?', ('accepted', invite['id']))
    log_event(conn, 'team_invite_accepted', user_id=session['user_id'], details={'team_id': invite['team_id'], 'invite_code': invite_code})
    conn.commit()
    conn.close()
    flash('Invite accepted. You have joined the team.', 'success')
    return redirect(url_for('dashboard'))

# --- Background Task: Automated Resource Management ---
def cleanup_idle_containers():
    print("Running background task: Cleaning up old containers...")
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # We'll just define an "idle" container as any container that has been
    # running for more than 2 hours. In a real scenario, we might track last_active time.
    # For now, we will simply stop them if they've been running while we check.
    # To keep it simple, we just stop all 'running' containers periodically,
    # forcing users to resume them if they are still active.
    # Or, querying Docker SDK for container uptime.
    
    # Simplified approach: If a container status in DB is running, check its actual status.
    running_containers = cursor.execute("SELECT id, container_id, user_id FROM containers WHERE status = 'running'").fetchall()
    
    from utils.docker_manager import get_client
    client = get_client()
    if client:
        for record in running_containers:
            try:
                # We could check exactly how long it's been running via client.containers.get().attrs['State']['StartedAt']
                # But let's just forcefully stop everything every X hours as a hard reset for safety.
                container = client.containers.get(record['container_id'])
                # If we want a 2-hour limit, we'd parse the date. Let's just do a 2-hour hard limit.
                import datetime
                from dateutil.parser import parse
                started_at = parse(container.attrs['State']['StartedAt'])
                now = datetime.datetime.now(datetime.timezone.utc)
                diff = now - started_at
                
                if diff.total_seconds() > 7200: # 2 hours
                    print(f"Stopping container {record['container_id']} (User {record['user_id']}) because it exceeded 2 hours limit.")
                    container.stop()
                    cursor.execute("UPDATE containers SET status = 'exited' WHERE id = ?", (record['id'],))
            except Exception as e:
                print(f"Error checking/stopping container {record['container_id']}: {e}")
                
    conn.commit()
    conn.close()

if __name__ == '__main__':
    # Initialize Scheduler
    scheduler = BackgroundScheduler()
    # Run cleanup every 10 minutes
    scheduler.add_job(func=cleanup_idle_containers, trigger="interval", minutes=10)
    # Rotate old snapshots based on per-user retention policies.
    scheduler.add_job(func=cleanup_snapshot_retention, trigger="interval", minutes=30)
    scheduler.start()
    
    try:
        app.run(host='0.0.0.0', port=5000, debug=False) # Debug mode interacts poorly with APScheduler
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown()
