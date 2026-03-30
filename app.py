from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import json
import requests
from werkzeug.security import generate_password_hash, check_password_hash
import os
import time
from apscheduler.schedulers.background import BackgroundScheduler
from utils.docker_manager import start_container, stop_container, resume_container, remove_container, get_container_status, LAB_CONFIGS

app = Flask(__name__)
app.secret_key = 'super_secret_cyber_lab_key'
DB_PATH = 'database.db'

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

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
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    try:
        cursor.execute("ALTER TABLE containers ADD COLUMN lab_type TEXT NOT NULL DEFAULT 'juice-shop'")
    except sqlite3.OperationalError:
        pass # Column likely exists already
        
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
    # Seed a dummy flag if table is empty
    count = cursor.execute('SELECT COUNT(*) FROM flags').fetchone()[0]
    if count == 0:
        cursor.execute("INSERT INTO flags (flag_value, points) VALUES ('FLAG{DVWA-MASTER-HACKER}', 50)")

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
            conn.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', 
                         (username, password_hash))
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
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials.", "danger")
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    user_id = session['user_id']
    username = session['username']
    
    conn = get_db_connection()
    container_record = conn.execute('SELECT * FROM containers WHERE user_id = ?', (user_id,)).fetchone()
    
    # Leaderboard Data
    leaderboard = conn.execute('SELECT username, score FROM users ORDER BY score DESC LIMIT 10').fetchall()
    
    conn.close()
    
    container_info = None
    if container_record:
        real_status = get_container_status(container_record['container_id'])
        container_info = {
            'id': container_record['id'],
            'container_id': container_record['container_id'],
            'port': container_record['port'],
            'status': real_status,
            'lab_type': dict(container_record).get('lab_type', 'juice-shop')
        }
        
        if real_status != container_record['status']:
            conn = get_db_connection()
            conn.execute('UPDATE containers SET status = ? WHERE id = ?', (real_status, container_record['id']))
            conn.commit()
            conn.close()
            
    return render_template('dashboard.html', username=username, container=container_info, leaderboard=leaderboard, labs=LAB_CONFIGS)

@app.route('/webhook/<int:user_id>', methods=['POST', 'PUT'])
def webhook(user_id):
    # Depending on how Juice Shop sends the CTF webhook, it might be POST or PUT
    data = request.json or {}
    
    # Simple validation: just give 10 points for a valid challenge solve webhook
    conn = get_db_connection()
    # Update score
    conn.execute('UPDATE users SET score = score + 10 WHERE id = ?', (user_id,))
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
    existing = conn.execute('SELECT * FROM containers WHERE user_id = ?', (user_id,)).fetchone()
    
    if existing:
        # Check if container actually exists in docker
        real_status = get_container_status(existing['container_id'])
        if real_status not in ['not_found', 'error', 'error_docker_not_running']:
            if real_status == 'exited':
                # Re-start the existing container
                resume_container(existing['container_id'])
                conn.execute('UPDATE containers SET status = ? WHERE id = ?', ('running', existing['id']))
                conn.commit()
                flash("Your existing lab has been resumed.", "success")
            else:
                flash("You already have an assigned lab.", "warning")
            conn.close()
            return redirect(url_for('dashboard'))
        elif real_status == 'error_docker_not_running':
             flash("Docker is not running on the server.", "danger")
             conn.close()
             return redirect(url_for('dashboard'))
        else:
            # container not found or error, just remove from DB and continue
            conn.execute('DELETE FROM containers WHERE user_id = ?', (user_id,))
            conn.commit()
            
    max_port_record = conn.execute('SELECT MAX(port) as max_p FROM containers').fetchone()
    if max_port_record and max_port_record['max_p'] and max_port_record['max_p'] >= 3001:
        port = max_port_record['max_p'] + 1
    else:
        port = 3001
        
    try:
        container_id = start_container(port, user_id, lab_type)
        conn.execute('INSERT INTO containers (user_id, container_id, port, status, lab_type) VALUES (?, ?, ?, ?, ?)',
                     (user_id, container_id, port, 'running', lab_type))
        conn.commit()
        flash("Lab started successfully! It may take a moment to become fully accessible.", "success")
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
    
    conn = get_db_connection()
    existing = conn.execute('SELECT * FROM containers WHERE user_id = ?', (user_id,)).fetchone()
    
    if existing:
        try:
            stop_container(existing['container_id'])
            conn.execute('UPDATE containers SET status = ? WHERE user_id = ?', ('exited', user_id))
            conn.commit()
            flash("Lab stopped.", "success")
        except Exception as e:
            flash(f"Failed to stop lab: {str(e)}", "danger")
    
    conn.close()
    return redirect(url_for('dashboard'))

@app.route('/reset_lab', methods=['POST'])
def reset_lab():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    user_id = session['user_id']
    
    conn = get_db_connection()
    existing = conn.execute('SELECT * FROM containers WHERE user_id = ?', (user_id,)).fetchone()
    
    if existing:
        old_container_id = existing['container_id']
        port = existing['port']
        
        try:
            remove_container(old_container_id)
            new_container_id = start_container(port, user_id, dict(existing).get('lab_type', 'juice-shop'))
            
            conn.execute('UPDATE containers SET container_id = ?, status = ? WHERE user_id = ?', 
                         (new_container_id, 'running', user_id))
            conn.commit()
            flash("Lab reset successfully. This is a fresh instance.", "success")
            
        except Exception as e:
            flash(f"Failed to reset lab: {str(e)}", "danger")
            
    conn.close()
    return redirect(url_for('dashboard'))

@app.route('/destroy_lab', methods=['POST'])
def destroy_lab():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    user_id = session['user_id']
    
    conn = get_db_connection()
    existing = conn.execute('SELECT * FROM containers WHERE user_id = ?', (user_id,)).fetchone()
    
    if existing:
        old_container_id = existing['container_id']
        try:
            remove_container(old_container_id)
            conn.execute('DELETE FROM containers WHERE user_id = ?', (user_id,))
            conn.commit()
            flash("Lab destroyed successfully. You can now select a new lab engine.", "success")
        except Exception as e:
            flash(f"Failed to destroy lab: {str(e)}", "danger")
            
    conn.close()
    return redirect(url_for('dashboard'))

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
            flash("You have already claimed this flag!", "warning")
        else:
            conn.execute('INSERT INTO solved_flags (user_id, flag_id) VALUES (?, ?)', (user_id, flag_id))
            conn.execute('UPDATE users SET score = score + ? WHERE id = ?', (points, user_id))
            conn.commit()
            flash(f"Flag Accepted! You earned {points} points.", "success")
    else:
        flash("Invalid flag. Keep trying!", "danger")
        
    conn.close()
    return redirect(url_for('dashboard'))

@app.route('/proxy_guide')
def proxy_guide():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    user_id = session['user_id']
    conn = get_db_connection()
    container_record = conn.execute('SELECT * FROM containers WHERE user_id = ?', (user_id,)).fetchone()
    conn.close()
    
    container_info = None
    if container_record:
        real_status = get_container_status(container_record['container_id'])
        container_info = {
            'port': container_record['port'],
            'status': real_status,
            'lab_type': dict(container_record).get('lab_type', 'juice-shop')
        }
    
    return render_template('proxy_guide.html', container=container_info)

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
    scheduler.start()
    
    try:
        app.run(host='0.0.0.0', port=5000, debug=False) # Debug mode interacts poorly with APScheduler
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown()
