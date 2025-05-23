from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash, send_from_directory
from flask_socketio import SocketIO, emit, join_room
from werkzeug.utils import secure_filename
import os , openai
import mysql.connector
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env
print("OPENAI_API_KEY:", os.getenv("OPENAI_API_KEY"))
openai.api_key = os.getenv("OPENAI_API_KEY")


app = Flask(__name__)
app.secret_key = 'your_secret_key'
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
socketio = SocketIO(app, cors_allowed_origins="*")


# MySQL Configuration
def get_db_connection():
    try:
        conn = mysql.connector.connect(
            host='localhost',
            user='root',
            password='',
            database='notes_db'
        )
        return conn
    except mysql.connector.Error as err:
        print(f"Error connecting to database: {err}")
        return None

conn = get_db_connection()
cursor = conn.cursor(dictionary=True)


@app.route('/')
def home():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Get all departments (streams)
    cursor.execute("SELECT DISTINCT stream FROM notes WHERE status = 'approved'")
    departments = [row['stream'] for row in cursor.fetchall()]

    # Get latest 10 approved notes with uploader's name
    cursor.execute("""
        SELECT notes.*, users.first_name, users.last_name
        FROM notes
        JOIN users ON notes.user_id = users.id
        WHERE notes.status = 'approved'
        ORDER BY notes.id DESC
        LIMIT 10
    """)
    notes = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('index.html', notes=notes, departments=departments)


@app.route('/department/<string:stream>')
def department_notes(stream):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT n.*, u.first_name, u.last_name
        FROM notes n
        JOIN users u ON n.user_id = u.id
        WHERE n.stream = %s AND n.status = 'approved'
        ORDER BY n.id DESC
    """, (stream,))
    notes = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('department_notes.html', notes=notes, stream=stream)



@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        phone = request.form['phone']
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO users (first_name, last_name, email, phone, username, password, role)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (first_name, last_name, email, phone, username, password, role))
        conn.commit()
        cursor.close()
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check for admin
        cursor.execute("SELECT * FROM admin WHERE username=%s AND password=%s", (username, password))
        admin = cursor.fetchone()
        if admin:
            session['admin_id'] = admin['id']
            session['role'] = 'admin'
            flash("Admin login successful", "success")
            return redirect(url_for('home'))  # Redirect to the home page with admin navigation

        # Check for user
        cursor.execute("SELECT * FROM users WHERE username=%s AND password=%s", (username, password))
        user = cursor.fetchone()
        if user:
            session['user_id'] = user['id']
            session['role'] = 'user'
            flash("User login successful", "success")
            return redirect(url_for('home'))  # Redirect to the home page with user navigation

        flash("Invalid username or password", "danger")
        return redirect(url_for('login'))  # Redirect to login if invalid credentials

    return render_template("login.html")


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))


@app.route('/user/dashboard')
def user_dashboard():
    if 'user_id' not in session or session['role'] != 'user':
        return redirect(url_for('login'))
    
    # Get user's uploaded notes
    cursor.execute("SELECT * FROM notes WHERE user_id = %s", (session['user_id'],))
    notes = cursor.fetchall()

    # Get admin ID (assuming only one admin)
    cursor.execute("SELECT id FROM users WHERE role = 'admin' LIMIT 1")
    admin = cursor.fetchone()
    admin_id = admin['id'] if admin else None

    return render_template('user_dashboard.html', notes=notes, admin_id=admin_id)


@app.route('/user/upload', methods=['GET', 'POST'])
def upload_note():
    if request.method == 'POST':
        title = request.form['title']
        subject = request.form['subject']
        stream = request.form['stream']
        file = request.files['file']
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        cursor.execute("INSERT INTO notes (user_id, title, subject, stream, filename, status) VALUES (%s, %s, %s, %s, %s, 'pending')", 
                       (session['user_id'], title, subject, stream, filename))
        conn.commit()
        flash('Note uploaded and pending admin approval')
        return redirect(url_for('user_dashboard'))
    return render_template('upload_note.html')


@app.route('/user/download/<int:note_id>')
def download_note(note_id):
    cursor.execute("SELECT filename FROM notes WHERE id = %s", (note_id,))
    note = cursor.fetchone()
    if note:
        return send_from_directory(app.config['UPLOAD_FOLDER'], note['filename'], as_attachment=True)
    return 'File not found'


@app.route('/user/delete/<int:note_id>')
def delete_note(note_id):
    cursor.execute("DELETE FROM notes WHERE id = %s AND user_id = %s", (note_id, session['user_id']))
    conn.commit()
    flash('Note deleted')
    return redirect(url_for('user_dashboard'))


@app.route('/user/change_password', methods=['GET', 'POST'])
def user_change_password():
    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        user_id = session.get('user_id')

        cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))
        user = cursor.fetchone()

        if user and user['password'] == old_password:
            if new_password == confirm_password:
                cursor.execute("UPDATE users SET password=%s WHERE id=%s", (new_password, user_id))
                conn.commit()
                flash("Password changed successfully!", "success")
            else:
                flash("New passwords do not match.", "danger")
        else:
            flash("Old password is incorrect.", "danger")

        cursor.close()
        conn.close()

    return render_template('user_change_password.html')


@app.route('/admin/dashboard')
def admin_dashboard():
    if 'admin_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    cursor.execute("""
        SELECT notes.*, users.first_name, users.last_name 
        FROM notes 
        JOIN users ON notes.user_id = users.id
    """)
    notes = cursor.fetchall()

    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()

    return render_template('admin_dashboard.html', notes=notes, users=users)


@app.route('/admin/delete_note/<int:note_id>')
def admin_delete_note(note_id):
    cursor.execute("DELETE FROM notes WHERE id = %s", (note_id,))
    conn.commit()
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/delete_user/<int:user_id>')
def admin_delete_user(user_id):
    cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
    conn.commit()
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/change_password', methods=['GET', 'POST'])
def admin_change_password():
    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        admin_id = session.get('admin_id')

        conn = mysql.connector.connect(user='root', password='yourpass', host='localhost', database='yourdb')
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM admin WHERE id=%s", (admin_id,))
        admin = cursor.fetchone()

        if admin and admin['password'] == old_password:
            if new_password == confirm_password:
                cursor.execute("UPDATE admin SET password=%s WHERE id=%s", (new_password, admin_id))
                conn.commit()
                flash("Password changed successfully!", "success")
            else:
                flash("New passwords do not match.", "danger")
        else:
            flash("Old password is incorrect.", "danger")

        cursor.close()
        conn.close()

    return render_template('admin_change_password.html')


@app.route('/admin/update_status/<int:note_id>/<string:status>')
def update_note_status(note_id, status):
    cursor.execute("UPDATE notes SET status = %s WHERE id = %s", (status, note_id))
    conn.commit()
    return redirect(url_for('admin_dashboard'))


@app.route('/user/preview/<int:note_id>')
def preview_note(note_id):
    user_id = session.get('user_id')
    if not user_id or session.get('role') != 'user':
        flash("Please log in as a user to preview notes.", "danger")
        return redirect(url_for('login'))

    cursor.execute("SELECT filename FROM notes WHERE id = %s AND user_id = %s", (note_id, user_id))
    note = cursor.fetchone()
    if note:
        filename = secure_filename(note['filename'])
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if os.path.exists(filepath):
            return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
        else:
            flash("File not found on server.", "danger")
            return redirect(url_for('user_dashboard'))
    else:
        flash("Note not found or you don't have permission to preview it.", "danger")
        return redirect(url_for('user_dashboard'))



@app.route('/admin/preview/<int:note_id>')
def preview_notes(note_id):
    cursor.execute("SELECT filename FROM notes WHERE id = %s", (note_id,))
    note = cursor.fetchone()
    if note:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], note['filename'])
        if os.path.exists(file_path):
            return send_from_directory(app.config['UPLOAD_FOLDER'], note['filename'])
    return 'File not found'


@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query')
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Adjust this line based on real columns in your 'notes' table
    sql = "SELECT * FROM notes WHERE title LIKE %s OR filename LIKE %s"
    search_term = f"%{query}%"
    cursor.execute(sql, (search_term, search_term))
    results = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('search_results.html', query=query, notes=results)

@app.route('/chat/<int:receiver_id>')
def chat(receiver_id):
    if 'user_id' not in session:
        return redirect('/login')

    sender_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Get chat messages between sender and receiver
    cursor.execute("""
        SELECT cm.*, u.username AS sender_username 
        FROM chat_messages cm
        JOIN users u ON cm.sender_id = u.id
        WHERE (cm.sender_id = %s AND cm.receiver_id = %s) 
           OR (cm.sender_id = %s AND cm.receiver_id = %s)
        ORDER BY cm.timestamp
    """, (sender_id, receiver_id, receiver_id, sender_id))
    messages = cursor.fetchall()

    # Mark messages as read
    cursor.execute("""
        UPDATE chat_messages 
        SET is_read = TRUE 
        WHERE receiver_id = %s AND sender_id = %s AND is_read = FALSE
    """, (sender_id, receiver_id))
    conn.commit()

    # Get receiver info
    cursor.execute("SELECT first_name, last_name, username FROM users WHERE id = %s", (receiver_id,))
    receiver = cursor.fetchone()

    # Get sender username
    cursor.execute("SELECT username FROM users WHERE id = %s", (sender_id,))
    sender = cursor.fetchone()
    sender_username = sender['username']

    cursor.close()
    conn.close()

    return render_template('chat.html', messages=messages, receiver=receiver, receiver_id=receiver_id, sender_username=sender_username)

@socketio.on('send_message')
def handle_send_message(data):
    sender_id = session.get('user_id')
    receiver_id = data['receiver_id']
    message = data['message']
    room = data['room']
    sender_username = data['sender_username']  # ✅ From JS

    # Save to DB
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO chat_messages (sender_id, receiver_id, message, is_read) 
        VALUES (%s, %s, %s, %s)
    """, (sender_id, receiver_id, message, False))
    conn.commit()
    cursor.close()
    conn.close()

    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Emit to room
    emit('receive_message', {
        'sender_username': sender_username,
        'message': message,
        'timestamp': timestamp
    }, room=room)




@socketio.on('join_room')
def on_join(data):
    room = data['room']
    join_room(room)
    print(f"User {session.get('user_id')} joined room {room}")

    
@app.route('/users')
def user_list():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    sender_id = session['user_id']
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Get users excluding the current user, include full name and unread count
    cursor.execute("""
        SELECT u.id, u.first_name, u.last_name,
               (SELECT COUNT(*) FROM chat_messages 
                WHERE receiver_id = u.id AND sender_id = %s AND is_read = FALSE) AS unread_count
        FROM users u
        WHERE u.id != %s
    """, (sender_id, sender_id))

    users = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('user_list.html', users=users)


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/user/profile', methods=['GET', 'POST'])
def user_profile():
    if 'user_id' not in session or session.get('role') != 'user':
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        phone = request.form['phone']

        cursor.execute("""
            UPDATE users 
            SET first_name = %s, last_name = %s, email = %s, phone = %s 
            WHERE id = %s
        """, (first_name, last_name, email, phone, user_id))
        conn.commit()
        flash("Profile updated successfully!", "success")

    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    return render_template('user_profile.html', user=user)

@app.route('/admin/profile', methods=['GET', 'POST'])
def admin_profile():
    if 'admin_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    admin_id = session['admin_id']
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    if request.method == 'POST':
        username = request.form['username']

        cursor.execute("UPDATE admin SET username = %s WHERE id = %s", (username, admin_id))
        conn.commit()
        flash("Profile updated successfully!", "success")

    cursor.execute("SELECT * FROM admin WHERE id = %s", (admin_id,))
    admin = cursor.fetchone()

    cursor.close()
    conn.close()

    return render_template('admin_profile.html', admin=admin)


@app.route('/openai_chat', methods=['POST'])
def openai_chat():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.get_json()
    user_input = data.get('message')

    try:
        response = openai.ChatCompletion.create(
            model="gpt-4o-mini",  # or "gpt-4" if enabled
            messages=[
                {"role": "system", "content": "You are a helpful assistant for students."},
                {"role": "user", "content": user_input}
            ]
        )
        reply = response['choices'][0]['message']['content']
        return jsonify({'response': reply})

    except Exception as e:
        print(f"OpenAI API error: {e}")
        return jsonify({'error': 'OpenAI API request failed'}), 500


@app.route('/openai')
def openai_ui():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('openai_chat.html')


if __name__ == '__main__':
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
   
    socketio.run(app, debug=True)

