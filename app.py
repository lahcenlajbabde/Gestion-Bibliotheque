import logging
import os
import sqlite3
import sys
from contextlib import closing
from pathlib import Path

from flask import Flask, Response, render_template, request, redirect, url_for, session
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from flask import send_from_directory

# Use the conventional `static` folder. Static files should be placed under ./static/.
app = Flask(__name__, static_folder='static')
app.config['SECRET_KEY'] = 'bibliotheque-secret-key'

BASE_DIR = Path(__file__).resolve().parent
DATABASE_DIR = BASE_DIR / 'database'
DATABASE_PATH = DATABASE_DIR / 'users.db'
PROFILE_UPLOAD_DIR = BASE_DIR / 'static' / 'images' / 'profiles'
DATABASE_DIR.mkdir(exist_ok=True)
PROFILE_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'tiff', 'tif', 'svg', 'ico', 'jfif'}
# document upload dirs
DOC_PDF_DIR = BASE_DIR / 'uploads' / 'pdf'
DOC_COVERS_DIR = BASE_DIR / 'static' / 'images' / 'covers'
DOC_PDF_DIR.mkdir(parents=True, exist_ok=True)
DOC_COVERS_DIR.mkdir(parents=True, exist_ok=True)
ALLOWED_DOC_EXTENSIONS = {'pdf'}

log_file_path = os.path.join(os.path.dirname(__file__), 'form_submissions.log')
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_file_path, encoding='utf-8')
    ]
)
print(f"Logging to terminal and {log_file_path}")


def is_db_valid(path: Path) -> bool:
    if not path.exists():
        return False

    try:
        with sqlite3.connect(path, timeout=30) as conn:
            conn.execute('PRAGMA busy_timeout=30000;')
            cur = conn.cursor()
            cur.execute('PRAGMA integrity_check;')
            result = cur.fetchone()
            return result == ('ok',)
    except sqlite3.DatabaseError:
        return False


def repair_db(path: Path):
    if path.exists():
        corrupt_path = path.with_suffix('.corrupt.db')
        if corrupt_path.exists():
            corrupt_path.unlink()
        path.replace(corrupt_path)
        logging.warning('Corrupted SQLite database moved to %s', corrupt_path)


def init_db():
    with sqlite3.connect(app.config.get('DATABASE', str(DATABASE_PATH)), timeout=30) as conn:
        conn.execute('PRAGMA busy_timeout=30000;')
        conn.execute('PRAGMA journal_mode=WAL;')
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fullname TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                phone TEXT,
                profession TEXT,
                bio TEXT,
                profile_image TEXT,
                role TEXT DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.commit()

        # ensure users table columns exist (for upgrades)
        cursor = conn.cursor()
        cursor.execute('PRAGMA table_info(users)')
        existing_columns = {row[1] for row in cursor.fetchall()}
        for column in ['phone', 'profession', 'bio', 'profile_image', 'role']:
            if column not in existing_columns:
                conn.execute(f'ALTER TABLE users ADD COLUMN {column} TEXT')

        # ensure documents table columns exist (for upgrades)
        cursor = conn.cursor()
        cursor.execute('PRAGMA table_info(documents)')
        existing_doc_columns = {row[1] for row in cursor.fetchall()}
        for column in ['category', 'summary']:
            if column not in existing_doc_columns:
                conn.execute(f'ALTER TABLE documents ADD COLUMN {column} TEXT')

        # create documents table
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                author TEXT,
                filename TEXT NOT NULL,
                cover_image TEXT,
                category TEXT,
                summary TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        # create comments table
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                fullname TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                admin_response TEXT,
                responded_at TIMESTAMP,
                admin_name TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
            """
        )

        # ensure comments table columns exist (for upgrades)
        cursor = conn.cursor()
        cursor.execute('PRAGMA table_info(comments)')
        existing_comment_columns = {row[1] for row in cursor.fetchall()}
        for column in ['admin_response', 'responded_at', 'admin_name']:
            if column not in existing_comment_columns:
                conn.execute(f'ALTER TABLE comments ADD COLUMN {column} TEXT')

        conn.commit()


if not is_db_valid(DATABASE_PATH):
    repair_db(DATABASE_PATH)
    init_db()
else:
    init_db()


def get_db():
    conn = sqlite3.connect(
        app.config.get('DATABASE', str(DATABASE_PATH)),
        timeout=30,
    )
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys=ON;')
    conn.execute('PRAGMA busy_timeout=30000;')
    return conn


from functools import wraps
from flask import abort


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        role = session.get('role')
        if role != 'admin':
            return abort(403)
        return f(*args, **kwargs)
    return decorated


@app.route("/")
def home():
    if session.get('user_id'):
        role = session.get('role', 'user')
        if role == 'admin':
            return redirect(url_for('dashboard_admin'))
        return redirect(url_for('dashboard_user'))
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    message = None
    if request.method == "POST":
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        logging.info("[POST] /login email=%s", email)

        if not email or not password:
            message = "Veuillez remplir tous les champs."
        else:
            with closing(get_db()) as conn:
                user = conn.execute(
                    'SELECT * FROM users WHERE email = ?', (email,)
                ).fetchone()

            if user and check_password_hash(user['password_hash'], password):
                session.clear()
                session['user_id'] = user['id']
                session['role'] = user['role'] if user['role'] else 'user'
                session['user_fullname'] = user['fullname']
                session['user_email'] = user['email']
                return redirect(url_for('dashboard'))
            message = "Email ou mot de passe invalide."
    return render_template("login.html", message=message)


@app.route("/register", methods=["GET", "POST"])
def register():
    message = None
    if request.method == "POST":
        register_data = request.form.to_dict()
        logging.info("[POST] /register %s", register_data)

        fullname = register_data.get('fullname', '').strip()
        email = register_data.get('email', '').strip().lower()
        password = register_data.get('password', '')
        confirm_password = register_data.get('confirm-password', '')

        if not fullname or not email or not password:
            message = "Veuillez remplir tous les champs."
        elif password != confirm_password:
            message = "Les mots de passe ne correspondent pas."
        else:
            with closing(get_db()) as conn:
                existing_user = conn.execute(
                    'SELECT id FROM users WHERE email = ?', (email,)
                ).fetchone()

                if existing_user:
                    message = "Cet email est déjà utilisé."
                else:
                    role = 'user'
                    conn.execute(
                        'INSERT INTO users (fullname, email, password_hash, role) VALUES (?, ?, ?, ?)',
                        (fullname, email, generate_password_hash(password), role)
                    )
                    conn.commit()
                    user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
                    if user:
                        session.clear()
                        session['user_id'] = user['id']
                        session['role'] = user['role'] if user['role'] else 'user'
                        session['user_fullname'] = user['fullname']
                        session['user_email'] = user['email']
                        if session['role'] == 'admin':
                            return redirect(url_for('dashboard_admin'))
                        else:
                            return redirect(url_for('dashboard_user'))

    return render_template("register.html", message=message)


@app.route("/apropos")
def apropos():
    return render_template("Apropos.html")


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS


def allowed_doc_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_DOC_EXTENSIONS


@app.route('/dashboard-user', methods=['GET', 'POST'])
@login_required
def dashboard_user():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    message = None
    with closing(get_db()) as conn:
        user = conn.execute(
            'SELECT id, fullname, email, phone, profession, bio, profile_image, role, created_at FROM users WHERE id = ?', (user_id,)
        ).fetchone()

        if not user:
            session.clear()
            return redirect(url_for('login'))

        if request.method == 'POST':
            phone = request.form.get('phone', '').strip()
            profession = request.form.get('profession', '').strip()
            bio = request.form.get('bio', '').strip()
            profile_image = user['profile_image'] or ''

            uploaded_file = request.files.get('profile_image')
            if uploaded_file and uploaded_file.filename:
                if allowed_file(uploaded_file.filename):
                    filename = secure_filename(uploaded_file.filename)
                    save_path = PROFILE_UPLOAD_DIR / filename
                    uploaded_file.save(save_path)
                    profile_image = filename
                else:
                    message = 'Type de fichier non autorisé pour la photo de profil.'

            if message is None:
                conn.execute(
                    'UPDATE users SET phone = ?, profession = ?, bio = ?, profile_image = ? WHERE id = ?',
                    (phone, profession, bio, profile_image, user_id)
                )
                conn.commit()
                message = 'Profil mis à jour avec succès.'
                user = conn.execute(
                    'SELECT id, fullname, email, phone, profession, bio, profile_image, role, created_at FROM users WHERE id = ?', (user_id,)
                ).fetchone()

    return render_template('dashboard_user.html', user=dict(user), message=message)


@app.route('/dashboard-admin')
@login_required
@admin_required
def dashboard_admin():
    with closing(get_db()) as conn:
        total_users = conn.execute('SELECT COUNT(*) as c FROM users').fetchone()['c']
    return render_template('dashboard_admin.html', fullname=session.get('user_fullname'), total_users=total_users)


@app.route('/dashboard')
@login_required
def dashboard():
    role = session.get('role', 'user')
    if role == 'admin':
        return redirect(url_for('dashboard_admin'))
    return redirect(url_for('dashboard_user'))


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/users')
def users():
    with closing(get_db()) as conn:
        rows = conn.execute('SELECT id, fullname, email, created_at FROM users ORDER BY id').fetchall()
    users = [dict(row) for row in rows]

    return render_template('users.html', users=users)


@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    with closing(get_db()) as conn:
        rows = conn.execute("SELECT id, fullname, email, role, created_at FROM users ORDER BY id").fetchall()
    users = [dict(r) for r in rows]
    return render_template('admin_users.html', users=users)


@app.route('/admin/users/promote/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def admin_promote(user_id):
    action = request.form.get('action', 'promote')
    with closing(get_db()) as conn:
        if action == 'promote':
            conn.execute('UPDATE users SET role = ? WHERE id = ?', ('admin', user_id))
        else:
            conn.execute('UPDATE users SET role = ? WHERE id = ?', ('user', user_id))
        conn.commit()
    return redirect(url_for('admin_users'))


@app.route('/admin/documents')
@login_required
@admin_required
def admin_documents():
    with closing(get_db()) as conn:
        rows = conn.execute("SELECT id, title, author, category, summary, filename, cover_image, created_at FROM documents ORDER BY id DESC").fetchall()
    docs = [dict(r) for r in rows]
    return render_template('admin_documents.html', documents=docs)


@app.route('/admin/documents/create', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_documents_create():
    message = None
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        author = request.form.get('author', '').strip()
        category = request.form.get('category', '').strip()
        summary = request.form.get('summary', '').strip()
        pdf_file = request.files.get('pdf_file')
        cover_file = request.files.get('cover_file')

        if not title or not pdf_file or not pdf_file.filename:
            message = 'Titre et fichier PDF requis.'
        elif not allowed_doc_file(pdf_file.filename):
            message = 'Seuls les PDF sont autorisés.'
        else:
            pdf_filename = secure_filename(pdf_file.filename)
            pdf_save = DOC_PDF_DIR / pdf_filename
            pdf_file.save(str(pdf_save))

            cover_filename = None
            if cover_file and cover_file.filename:
                if allowed_file(cover_file.filename):
                    cover_filename = secure_filename(cover_file.filename)
                    cover_file.save(str(DOC_COVERS_DIR / cover_filename))
                else:
                    message = 'Format de couverture non supporté. Utilisez PNG, JPG, JPEG, GIF, WEBP, BMP, TIFF, SVG ou ICO.'

            if message is None:
                with closing(get_db()) as conn:
                    conn.execute('INSERT INTO documents (title, author, category, summary, filename, cover_image) VALUES (?, ?, ?, ?, ?, ?)',
                                 (title, author, category, summary, pdf_filename, cover_filename))
                    conn.commit()
                return redirect(url_for('admin_documents'))

    return render_template('document_form.html', action='create', message=message, doc=None)


@app.route('/admin/documents/edit/<int:doc_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_documents_edit(doc_id):
    with closing(get_db()) as conn:
        doc = conn.execute('SELECT * FROM documents WHERE id = ?', (doc_id,)).fetchone()
        if not doc:
            return redirect(url_for('admin_documents'))

        message = None
        if request.method == 'POST':
            title = request.form.get('title', '').strip()
            author = request.form.get('author', '').strip()
            category = request.form.get('category', '').strip()
            summary = request.form.get('summary', '').strip()
            pdf_file = request.files.get('pdf_file')
            cover_file = request.files.get('cover_file')

            filename = doc['filename']
            cover = doc['cover_image']

            if pdf_file and pdf_file.filename:
                if allowed_doc_file(pdf_file.filename):
                    filename = secure_filename(pdf_file.filename)
                    pdf_file.save(str(DOC_PDF_DIR / filename))
                else:
                    message = 'Seuls les PDF sont autorisés.'

            if cover_file and cover_file.filename:
                if allowed_file(cover_file.filename):
                    cover = secure_filename(cover_file.filename)
                    cover_file.save(str(DOC_COVERS_DIR / cover))
                else:
                    message = 'Format de couverture non supporté. Utilisez PNG, JPG, JPEG, GIF, WEBP, BMP, TIFF, SVG ou ICO.'

            if message is None:
                conn.execute('UPDATE documents SET title = ?, author = ?, category = ?, summary = ?, filename = ?, cover_image = ? WHERE id = ?',
                             (title, author, category, summary, filename, cover, doc_id))
                conn.commit()
                return redirect(url_for('admin_documents'))

        return render_template('document_form.html', action='edit', message=message, doc=dict(doc))


@app.route('/admin/documents/delete/<int:doc_id>', methods=['POST'])
@login_required
@admin_required
def admin_documents_delete(doc_id):
    with closing(get_db()) as conn:
        conn.execute('DELETE FROM documents WHERE id = ?', (doc_id,))
        conn.commit()
    return redirect(url_for('admin_documents'))


@app.route('/documents/<int:doc_id>')
def view_document(doc_id):
    with closing(get_db()) as conn:
        doc = conn.execute('SELECT * FROM documents WHERE id = ?', (doc_id,)).fetchone()
    if not doc:
        return redirect(url_for('home'))
    return render_template('view_document.html', doc=dict(doc))


@app.route('/documents', methods=['GET', 'POST'])
@login_required
def documents():
    query = request.form.get('query', '').strip()
    with closing(get_db()) as conn:
        if query:
            rows = conn.execute(
                "SELECT id, title, author, category, summary, filename, cover_image FROM documents WHERE LOWER(title) LIKE ? OR LOWER(author) LIKE ? OR LOWER(category) LIKE ? ORDER BY id DESC",
                ('%' + query.lower() + '%', '%' + query.lower() + '%', '%' + query.lower() + '%')
            ).fetchall()
        else:
            rows = conn.execute("SELECT id, title, author, category, summary, filename, cover_image FROM documents ORDER BY id DESC").fetchall()
    docs = [dict(r) for r in rows]
    message = None
    if query and not docs:
        message = 'Document n\'existe pas.'
    comment_message = session.pop('comment_message', None)

    # Get the current user's comments with admin responses
    user_id = session.get('user_id')
    user_comments = []
    if user_id:
        with closing(get_db()) as conn:
            rows = conn.execute(
                "SELECT id, user_id, fullname, message, created_at, admin_response, responded_at, admin_name FROM comments WHERE user_id = ? ORDER BY created_at DESC",
                (user_id,)
            ).fetchall()
            user_comments = [dict(r) for r in rows]

    return render_template('documents.html', documents=docs, query=query, message=message, comment_message=comment_message, user_comments=user_comments)


@app.route('/submit-comment', methods=['POST'])
@login_required
def submit_comment():
    msg = request.form.get('message', '').strip()
    if not msg:
        return redirect(url_for('documents'))

    user_id = session.get('user_id')
    fullname = session.get('user_fullname', 'Utilisateur')
    with closing(get_db()) as conn:
        conn.execute(
            'INSERT INTO comments (user_id, fullname, message) VALUES (?, ?, ?)',
            (user_id, fullname, msg)
        )
        conn.commit()
    session['comment_message'] = 'Votre commentaire a été envoyé avec succès.'
    return redirect(url_for('documents'))


@app.route('/admin/comments')
@login_required
@admin_required
def admin_comments():
    with closing(get_db()) as conn:
        rows = conn.execute(
            "SELECT id, user_id, fullname, message, created_at, admin_response, responded_at, admin_name FROM comments ORDER BY created_at DESC"
        ).fetchall()
    comments = [dict(r) for r in rows]
    return render_template('admin_comments.html', comments=comments)


@app.route('/admin/comments/respond/<int:comment_id>', methods=['POST'])
@login_required
@admin_required
def admin_respond_comment(comment_id):
    response_text = request.form.get('response', '').strip()
    if not response_text:
        return redirect(url_for('admin_comments'))

    from datetime import datetime
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    admin_name = session.get('user_fullname', 'Administrateur')

    with closing(get_db()) as conn:
        conn.execute(
            'UPDATE comments SET admin_response = ?, responded_at = ?, admin_name = ? WHERE id = ?',
            (response_text, now, admin_name, comment_id)
        )
        conn.commit()
    return redirect(url_for('admin_comments'))


@app.route('/uploads/pdf/<path:filename>')
def uploaded_pdf(filename):
    return send_from_directory(str(DOC_PDF_DIR), filename)


@app.route('/uploads/covers/<path:filename>')
def uploaded_cover(filename):
    # Rediriger vers le fichier statique pour un service fiable
    return redirect(url_for('static', filename='images/covers/' + filename))


if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)