#!/usr/bin/env python3
import getpass
import sqlite3
from pathlib import Path
from werkzeug.security import generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / 'database' / 'users.db'

if not DB_PATH.exists():
    print(f"Database not found at {DB_PATH}")
    raise SystemExit(1)

def prompt(prompt_text, default=None):
    if default:
        return input(f"{prompt_text} [{default}]: ") or default
    return input(f"{prompt_text}: ")

email = prompt('Email de l\'admin à créer/promouvoir')
if not email:
    print('Email requis')
    raise SystemExit(1)

conn = sqlite3.connect(str(DB_PATH))
cur = conn.cursor()
cur.execute('PRAGMA foreign_keys = ON')
cur.execute('SELECT id, fullname, email, role FROM users WHERE email = ?', (email.lower(),))
row = cur.fetchone()

if row:
    print(f"Utilisateur trouvé: {row[1]} <{row[2]}> (role={row[3]})")
    confirm = input('Promouvoir cet utilisateur en admin ? (o/N): ').strip().lower()
    if confirm != 'o':
        print('Opération annulée')
        conn.close()
        raise SystemExit(0)
    cur.execute('UPDATE users SET role = ? WHERE id = ?', ('admin', row[0]))
    conn.commit()
    print('Utilisateur promu en admin.')
else:
    fullname = prompt('Nom complet')
    if not fullname:
        print('Nom requis')
        conn.close()
        raise SystemExit(1)
    password = getpass.getpass('Mot de passe (sera hashé): ')
    password2 = getpass.getpass('Confirmer mot de passe: ')
    if password != password2:
        print('Les mots de passe ne correspondent pas')
        conn.close()
        raise SystemExit(1)
    pw_hash = generate_password_hash(password)
    cur.execute('INSERT INTO users (fullname, email, password_hash, role) VALUES (?, ?, ?, ?)',
                (fullname, email.lower(), pw_hash, 'admin'))
    conn.commit()
    print('Compte admin créé.')

conn.close()
print('Terminé.')
