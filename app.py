import os
import base64
import hashlib
import secrets
import string
import json
import csv
import hmac
import sqlite3
from pathlib import Path
from io import BytesIO, StringIO
from datetime import datetime

import streamlit as st
import streamlit.components.v1 as components

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils

try:
    import qrcode
    from PIL import Image
    QR_AVAILABLE = True
except Exception:
    QR_AVAILABLE = False

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.lib.units import cm
    REPORTLAB_AVAILABLE = True
except Exception:
    REPORTLAB_AVAILABLE = False


# =====================================================
# CONFIGURATION
# =====================================================

st.set_page_config(
    page_title="CyberCrypt Enterprise Security Suite",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

PREFIX_MESSAGE = b"CYBERCRYPT_ENTERPRISE_MSG_V1::"
PREFIX_FILE = b"CYBERCRYPT_ENTERPRISE_FILE_V1::"
PREFIX_VAULT = b"CYBERCRYPT_ENTERPRISE_VAULT_V1::"

DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "cybercrypt_enterprise.db"
PBKDF2_ITERATIONS = 250_000



# =====================================================
# AUTHENTIFICATION / UTILISATEURS / AUDIT PERSISTANT
# =====================================================

def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password: str, salt_hex: str | None = None):
    salt = bytes.fromhex(salt_hex) if salt_hex else os.urandom(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS
    )
    return salt.hex(), digest.hex()


def verify_password(password: str, salt_hex: str, stored_hash: str) -> bool:
    _, computed = hash_password(password, salt_hex)
    return hmac.compare_digest(computed, stored_hash)


def log_audit(username: str, action: str, object_type: str, details: str = "", hash_value: str = "", status: str = "SUCCESS"):
    conn = get_db()
    conn.execute("""
        INSERT INTO audit_logs (timestamp, username, action, object_type, details, hash_value, status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (now_str(), username, action, object_type, details, hash_value, status))
    conn.commit()
    conn.close()


def create_user(username: str, full_name: str, password: str, role: str = "analyst", audit: bool = True):
    salt, pwd_hash = hash_password(password)
    conn = get_db()
    conn.execute("""
        INSERT INTO users (username, full_name, role, password_salt, password_hash, is_active, created_at)
        VALUES (?, ?, ?, ?, ?, 1, ?)
    """, (username, full_name, role, salt, pwd_hash, now_str()))
    conn.commit()
    conn.close()
    if audit:
        log_audit("system", "CREATE_USER", "user", f"Utilisateur créé : {username}", "", "SUCCESS")


def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        full_name TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'analyst',
        password_salt TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        username TEXT NOT NULL,
        action TEXT NOT NULL,
        object_type TEXT NOT NULL,
        details TEXT,
        hash_value TEXT,
        status TEXT NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS stored_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        operation TEXT NOT NULL,
        input_preview TEXT,
        output_text TEXT NOT NULL,
        hash_value TEXT,
        status TEXT NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS stored_files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        operation TEXT NOT NULL,
        filename TEXT NOT NULL,
        hash_value TEXT,
        status TEXT NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS stored_vault (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner TEXT NOT NULL,
        title TEXT NOT NULL,
        category TEXT NOT NULL,
        token TEXT NOT NULL,
        hash_value TEXT,
        created_at TEXT NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS stored_signatures (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        data_hash TEXT NOT NULL,
        signature TEXT NOT NULL,
        status TEXT NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS stored_qr (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        token TEXT NOT NULL,
        hash_value TEXT,
        status TEXT NOT NULL
    )
    """)

    cur.execute("SELECT COUNT(*) AS n FROM users")
    existing = cur.fetchone()["n"]
    conn.commit()
    conn.close()

    if existing == 0:
        create_user("admin", "Administrator", "admin123", "admin", audit=False)


def authenticate(username: str, password: str):
    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE username=? AND is_active=1",
        (username,)
    ).fetchone()
    conn.close()
    if not user:
        return None
    if verify_password(password, user["password_salt"], user["password_hash"]):
        return dict(user)
    return None


def fetch_users():
    conn = get_db()
    rows = conn.execute("""
        SELECT id, username, full_name, role, is_active, created_at
        FROM users
        ORDER BY id DESC
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def set_user_status(user_id: int, status: int):
    conn = get_db()
    conn.execute("UPDATE users SET is_active=? WHERE id=?", (status, user_id))
    conn.commit()
    conn.close()


def fetch_persistent_audit(limit: int = 500):
    conn = get_db()
    rows = conn.execute("""
        SELECT *
        FROM audit_logs
        ORDER BY id DESC
        LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def export_persistent_audit_csv(logs):
    output = StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=["id", "timestamp", "username", "action", "object_type", "details", "hash_value", "status"]
    )
    writer.writeheader()
    for row in logs:
        writer.writerow(row)
    return output.getvalue().encode("utf-8")



def store_message(owner: str, operation: str, input_preview: str, output_text: str, hash_value: str, status: str):
    conn = get_db()
    conn.execute("""
        INSERT INTO stored_messages (owner, timestamp, operation, input_preview, output_text, hash_value, status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (owner, now_str(), operation, input_preview[:500], output_text, hash_value, status))
    conn.commit()
    conn.close()


def fetch_messages(owner: str, limit: int = 20):
    conn = get_db()
    rows = conn.execute("""
        SELECT *
        FROM stored_messages
        WHERE owner = ?
        ORDER BY id DESC
        LIMIT ?
    """, (owner, limit)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def store_file_event(owner: str, operation: str, filename: str, hash_value: str, status: str):
    conn = get_db()
    conn.execute("""
        INSERT INTO stored_files (owner, timestamp, operation, filename, hash_value, status)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (owner, now_str(), operation, filename, hash_value, status))
    conn.commit()
    conn.close()


def fetch_file_events(owner: str, limit: int = 50):
    conn = get_db()
    rows = conn.execute("""
        SELECT *
        FROM stored_files
        WHERE owner = ?
        ORDER BY id DESC
        LIMIT ?
    """, (owner, limit)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def store_vault_item(owner: str, title: str, category: str, token: str, hash_value: str):
    conn = get_db()
    conn.execute("""
        INSERT INTO stored_vault (owner, title, category, token, hash_value, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (owner, title, category, token, hash_value, now_str()))
    conn.commit()
    conn.close()


def fetch_vault_items(owner: str):
    conn = get_db()
    rows = conn.execute("""
        SELECT *
        FROM stored_vault
        WHERE owner = ?
        ORDER BY id DESC
    """, (owner,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def store_signature(owner: str, data_hash: str, signature: str, status: str):
    conn = get_db()
    conn.execute("""
        INSERT INTO stored_signatures (owner, timestamp, data_hash, signature, status)
        VALUES (?, ?, ?, ?, ?)
    """, (owner, now_str(), data_hash, signature, status))
    conn.commit()
    conn.close()


def fetch_signatures(owner: str, limit: int = 20):
    conn = get_db()
    rows = conn.execute("""
        SELECT *
        FROM stored_signatures
        WHERE owner = ?
        ORDER BY id DESC
        LIMIT ?
    """, (owner, limit)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def store_qr(owner: str, token: str, hash_value: str, status: str):
    conn = get_db()
    conn.execute("""
        INSERT INTO stored_qr (owner, timestamp, token, hash_value, status)
        VALUES (?, ?, ?, ?, ?)
    """, (owner, now_str(), token, hash_value, status))
    conn.commit()
    conn.close()


def fetch_qr(owner: str, limit: int = 20):
    conn = get_db()
    rows = conn.execute("""
        SELECT *
        FROM stored_qr
        WHERE owner = ?
        ORDER BY id DESC
        LIMIT ?
    """, (owner, limit)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def count_table_for_owner(table_name: str, owner: str):
    allowed = {"stored_messages", "stored_files", "stored_vault", "stored_signatures", "stored_qr"}
    if table_name not in allowed:
        return 0
    conn = get_db()
    row = conn.execute(f"SELECT COUNT(*) AS n FROM {table_name} WHERE owner = ?", (owner,)).fetchone()
    conn.close()
    return row["n"]



# =====================================================
# CRYPTO — AES / PBKDF2
# =====================================================

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_bytes(data: bytes, password: str, aad: bytes | None = None, prefix: bytes = b"") -> bytes:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, aad)
    return base64.b64encode(prefix + salt + nonce + ciphertext)


def decrypt_bytes(token: bytes, password: str, aad: bytes | None = None, prefix: bytes = b"") -> bytes | None:
    try:
        payload = base64.b64decode(token)
        if prefix and not payload.startswith(prefix):
            return None
        if prefix:
            payload = payload.replace(prefix, b"", 1)
        salt = payload[:16]
        nonce = payload[16:28]
        ciphertext = payload[28:]
        key = derive_key(password, salt)
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, aad)
    except Exception:
        return None


# =====================================================
# CRYPTO — MESSAGES
# =====================================================

def encrypt_message(message: str, password: str) -> str:
    encrypted = encrypt_bytes(
        message.encode("utf-8"),
        password,
        aad=None,
        prefix=PREFIX_MESSAGE,
    )
    return encrypted.decode("utf-8")


def decrypt_message(token: str, password: str) -> str:
    decrypted = decrypt_bytes(
        token.encode("utf-8"),
        password,
        aad=None,
        prefix=PREFIX_MESSAGE,
    )
    if decrypted is None:
        return "ERROR"
    try:
        return decrypted.decode("utf-8")
    except Exception:
        return "ERROR"


def is_encrypted_message(text: str) -> bool:
    try:
        payload = base64.b64decode(text.encode("utf-8"))
        return payload.startswith(PREFIX_MESSAGE)
    except Exception:
        return False


# =====================================================
# CRYPTO — FICHIERS
# =====================================================

def encrypt_file(file_bytes: bytes, password: str, filename: str) -> bytes:
    filename_bytes = filename.encode("utf-8")
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    encrypted = aesgcm.encrypt(nonce, file_bytes, filename_bytes)
    payload = PREFIX_FILE + filename_bytes + b"::META::" + salt + nonce + encrypted
    return base64.b64encode(payload)


def decrypt_file(encrypted_bytes: bytes, password: str):
    try:
        payload = base64.b64decode(encrypted_bytes)
        if not payload.startswith(PREFIX_FILE):
            return None, None, "FORMAT_INVALID"
        payload = payload.replace(PREFIX_FILE, b"", 1)
        filename_bytes, encrypted_part = payload.split(b"::META::", 1)
        salt = encrypted_part[:16]
        nonce = encrypted_part[16:28]
        ciphertext = encrypted_part[28:]
        key = derive_key(password, salt)
        aesgcm = AESGCM(key)
        decrypted = aesgcm.decrypt(nonce, ciphertext, filename_bytes)
        return filename_bytes.decode("utf-8"), decrypted, "OK"
    except Exception:
        return None, None, "ERROR"


# =====================================================
# OUTILS CRYPTOGRAPHIQUES
# =====================================================

def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(file_bytes: bytes) -> str:
    return hashlib.sha256(file_bytes).hexdigest()


def caesar_encrypt(text: str, shift: int) -> str:
    result = ""
    for char in text:
        if char.isalpha():
            base = ord("A") if char.isupper() else ord("a")
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result


def caesar_decrypt(text: str, shift: int) -> str:
    return caesar_encrypt(text, -shift)


def generate_password(length: int = 18) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:,.?/|"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def password_strength(password: str):
    score = 0
    if len(password) >= 8:
        score += 15
    if len(password) >= 12:
        score += 20
    if len(password) >= 16:
        score += 15
    if any(c.isupper() for c in password):
        score += 10
    if any(c.islower() for c in password):
        score += 10
    if any(c.isdigit() for c in password):
        score += 15
    if any(c in "!@#$%^&*()-_=+[]{};:,.?/|" for c in password):
        score += 15
    score = min(score, 100)
    if score < 35:
        return score, "Faible"
    if score < 65:
        return score, "Correct"
    if score < 85:
        return score, "Fort"
    return score, "Très fort"


def crack_time_estimate(password: str) -> str:
    charset = 0
    if any(c.islower() for c in password):
        charset += 26
    if any(c.isupper() for c in password):
        charset += 26
    if any(c.isdigit() for c in password):
        charset += 10
    if any(c in "!@#$%^&*()-_=+[]{};:,.?/|" for c in password):
        charset += 30
    if charset == 0:
        return "Instantané"
    guesses = charset ** max(len(password), 1)
    guesses_per_second = 10**10
    seconds = guesses / guesses_per_second
    if seconds < 1:
        return "moins d'une seconde"
    if seconds < 60:
        return f"{seconds:.0f} secondes"
    minutes = seconds / 60
    if minutes < 60:
        return f"{minutes:.0f} minutes"
    hours = minutes / 60
    if hours < 24:
        return f"{hours:.0f} heures"
    days = hours / 24
    if days < 365:
        return f"{days:.0f} jours"
    years = days / 365
    if years < 1_000_000:
        return f"{years:.0f} ans"
    return "+1 million d'années"


# =====================================================
# RSA + SIGNATURE NUMÉRIQUE
# =====================================================

def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_key, public_key, private_pem, public_pem


def rsa_encrypt_text(text: str, public_key) -> str:
    encrypted = public_key.encrypt(
        text.encode("utf-8"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return base64.b64encode(encrypted).decode("utf-8")


def rsa_decrypt_text(token: str, private_key) -> str:
    try:
        encrypted = base64.b64decode(token.encode("utf-8"))
        decrypted = private_key.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return decrypted.decode("utf-8")
    except Exception:
        return "Erreur : déchiffrement RSA impossible."


def sign_data(data: bytes, private_key) -> str:
    signature = private_key.sign(
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode("utf-8")


def verify_signature(data: bytes, signature_b64: str, public_key) -> bool:
    try:
        signature = base64.b64decode(signature_b64.encode("utf-8"))
        public_key.verify(
            signature,
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


# =====================================================
# VAULT / COFFRE-FORT
# =====================================================

def encrypt_vault_item(item: dict, password: str) -> str:
    data = json.dumps(item, ensure_ascii=False).encode("utf-8")
    return encrypt_bytes(data, password, prefix=PREFIX_VAULT).decode("utf-8")


def decrypt_vault_item(token: str, password: str):
    decrypted = decrypt_bytes(token.encode("utf-8"), password, prefix=PREFIX_VAULT)
    if decrypted is None:
        return None
    try:
        return json.loads(decrypted.decode("utf-8"))
    except Exception:
        return None


# =====================================================
# EXPORTS / RAPPORTS
# =====================================================

def build_audit_records() -> list[dict]:
    records = []

    current_owner = None
    if st.session_state.get("user"):
        current_owner = st.session_state.user.get("username")

    if current_owner:
        for msg in fetch_messages(current_owner, 100):
            records.append({
                "date": msg.get("timestamp", ""),
                "type": msg.get("operation", "Message"),
                "objet": "Message sécurisé",
                "hash": msg.get("hash_value", "N/A"),
                "statut": msg.get("status", "OK"),
            })

        for item in fetch_file_events(current_owner, 100):
            records.append({
                "date": item.get("timestamp", ""),
                "type": item.get("operation", "Fichier"),
                "objet": item.get("filename", "Fichier"),
                "hash": item.get("hash_value", "N/A"),
                "statut": item.get("status", "OK"),
            })

        for item in fetch_vault_items(current_owner):
            records.append({
                "date": item.get("created_at", ""),
                "type": "Coffre-fort",
                "objet": item.get("title", "Secret"),
                "hash": item.get("hash_value", "N/A"),
                "statut": "OK",
            })

        for item in fetch_signatures(current_owner, 100):
            records.append({
                "date": item.get("timestamp", ""),
                "type": "Signature numérique",
                "objet": "Signature RSA-PSS",
                "hash": item.get("data_hash", "N/A"),
                "statut": item.get("status", "OK"),
            })

        for item in fetch_qr(current_owner, 100):
            records.append({
                "date": item.get("timestamp", ""),
                "type": "QR sécurisé",
                "objet": "Token chiffré",
                "hash": item.get("hash_value", "N/A"),
                "statut": item.get("status", "OK"),
            })

        return records

    # fallback si non connecté
    for msg in st.session_state.messages:
        if msg.get("role") == "assistant":
            records.append({
                "date": msg.get("time", ""),
                "type": msg.get("operation", "Message"),
                "objet": "Message sécurisé",
                "hash": msg.get("hash", "N/A"),
                "statut": "OK",
            })

    for item in st.session_state.file_history:
        records.append({
            "date": item.get("time", ""),
            "type": item.get("operation", "Fichier"),
            "objet": item.get("filename", "Fichier"),
            "hash": item.get("hash", "N/A"),
            "statut": "OK",
        })

    return records

def export_json_bytes(records: list[dict]) -> bytes:
    return json.dumps(records, ensure_ascii=False, indent=2).encode("utf-8")


def export_csv_bytes(records: list[dict]) -> bytes:
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=["date", "type", "objet", "hash", "statut"])
    writer.writeheader()
    for row in records:
        writer.writerow(row)
    return output.getvalue().encode("utf-8")


def generate_pdf_report(records: list[dict]) -> bytes | None:
    if not REPORTLAB_AVAILABLE:
        return None
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=2*cm, leftMargin=2*cm, topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("CustomTitle", parent=styles["Title"], textColor=colors.HexColor("#0f172a"), fontSize=20, leading=24)
    h_style = ParagraphStyle("Heading", parent=styles["Heading2"], textColor=colors.HexColor("#166534"), fontSize=14, leading=18)
    body = []
    body.append(Paragraph("CyberCrypt Enterprise Security Suite", title_style))
    body.append(Paragraph("Rapport de sécurité cryptographique", styles["Normal"]))
    body.append(Paragraph(f"Généré le : {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}", styles["Normal"]))
    body.append(Spacer(1, 0.5*cm))
    body.append(Paragraph("1. Objectif", h_style))
    body.append(Paragraph("Cette application démontre la protection de messages, fichiers, secrets et signatures numériques à l'aide de méthodes cryptographiques modernes.", styles["Normal"]))
    body.append(Spacer(1, 0.3*cm))
    body.append(Paragraph("2. Méthodes utilisées", h_style))
    data = [
        ["Méthode", "Usage", "Niveau"],
        ["AES-256-GCM", "Chiffrement messages/fichiers/coffre-fort", "Élevé"],
        ["PBKDF2", "Transformation mot de passe en clé", "Élevé"],
        ["SHA-256", "Empreinte et intégrité", "Élevé"],
        ["RSA", "Chiffrement asymétrique et signature", "Élevé"],
        ["César", "Démonstration historique", "Faible"],
    ]
    table = Table(data, colWidths=[4*cm, 8*cm, 3*cm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
    ]))
    body.append(table)
    body.append(Spacer(1, 0.5*cm))
    body.append(Paragraph("3. Journal d'audit", h_style))
    if records:
        audit_data = [["Date", "Type", "Objet", "Statut"]]
        for r in records[:25]:
            audit_data.append([r["date"], r["type"], r["objet"][:35], r["statut"]])
        audit_table = Table(audit_data, colWidths=[3*cm, 4*cm, 6*cm, 2*cm])
        audit_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#166534")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
        ]))
        body.append(audit_table)
    else:
        body.append(Paragraph("Aucune opération enregistrée pour le moment.", styles["Normal"]))
    body.append(Spacer(1, 0.5*cm))
    body.append(Paragraph("4. Conclusion", h_style))
    body.append(Paragraph("CyberCrypt Enterprise illustre une approche complète de sécurisation locale : confidentialité, intégrité, chiffrement, signature et traçabilité.", styles["Normal"]))
    doc.build(body)
    return buffer.getvalue()


def make_qr_image(text: str):
    if not QR_AVAILABLE:
        return None
    qr = qrcode.QRCode(version=None, box_size=8, border=3)
    qr.add_data(text)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    return buffer.getvalue()



def generate_persistent_audit_pdf(logs) -> bytes | None:
    if not REPORTLAB_AVAILABLE:
        return None

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=2*cm, leftMargin=2*cm, topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("AuditTitle", parent=styles["Title"], textColor=colors.HexColor("#0f172a"), fontSize=18, leading=22)
    heading_style = ParagraphStyle("AuditHeading", parent=styles["Heading2"], textColor=colors.HexColor("#166534"), fontSize=13, leading=17)

    body = []
    body.append(Paragraph("CyberCrypt Enterprise Security Suite", title_style))
    body.append(Paragraph("Journal d’audit persistant", heading_style))
    body.append(Paragraph(f"Généré le : {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}", styles["Normal"]))
    body.append(Spacer(1, 0.4*cm))

    data = [["Date", "Utilisateur", "Action", "Objet", "Statut"]]
    for row in logs[:45]:
        data.append([
            str(row.get("timestamp", ""))[:18],
            str(row.get("username", ""))[:15],
            str(row.get("action", ""))[:22],
            str(row.get("object_type", ""))[:14],
            str(row.get("status", ""))[:10],
        ])

    table = Table(data, colWidths=[3.2*cm, 3*cm, 4.2*cm, 2.5*cm, 2.2*cm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#166534")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    body.append(table)
    doc.build(body)
    return buffer.getvalue()



def copy_button(text: str, label: str, height: int = 52):
    safe_text = json.dumps(text)
    components.html(
        f"""
        <button onclick='navigator.clipboard.writeText({safe_text}); this.innerText="Copié ✅";'
            style="
                width:100%;
                height:42px;
                border-radius:12px;
                border:0;
                background:#2563eb;
                color:white;
                font-weight:800;
                cursor:pointer;
                font-family:Segoe UI;
            ">
            {label}
        </button>
        """,
        height=height,
    )


# =====================================================
# SESSION STATE
# =====================================================

init_db()

if "auth" not in st.session_state:
    st.session_state.auth = False

if "user" not in st.session_state:
    st.session_state.user = None


if "messages" not in st.session_state:
    st.session_state.messages = []
if "last_input" not in st.session_state:
    st.session_state.last_input = ""
if "last_result" not in st.session_state:
    st.session_state.last_result = ""
if "file_history" not in st.session_state:
    st.session_state.file_history = []
if "generated_password" not in st.session_state:
    st.session_state.generated_password = ""
if "vault_items" not in st.session_state:
    st.session_state.vault_items = []
if "vault_history" not in st.session_state:
    st.session_state.vault_history = []
if "signed_data" not in st.session_state:
    st.session_state.signed_data = ""
if "signature" not in st.session_state:
    st.session_state.signature = ""
if "signature_hash" not in st.session_state:
    st.session_state.signature_hash = ""
if "last_qr_saved" not in st.session_state:
    st.session_state.last_qr_saved = ""

if "rsa_private_key" not in st.session_state:
    private_key, public_key, private_pem, public_pem = generate_rsa_keys()
    st.session_state.rsa_private_key = private_key
    st.session_state.rsa_public_key = public_key
    st.session_state.rsa_private_pem = private_pem
    st.session_state.rsa_public_pem = public_pem


# =====================================================
# CSS ENTERPRISE
# =====================================================

st.markdown("""
<style>
.stApp {
    background: #050914;
    color: #E5E7EB;
    font-family: "Segoe UI", sans-serif;
}
[data-testid="stHeader"] { background: transparent; }
.block-container { max-width: 1420px; padding-top: 24px; padding-bottom: 40px; }
h1, h2, h3, p, label { color: #E5E7EB !important; }
.header-card {
    background: radial-gradient(circle at right, rgba(34,197,94,0.20), transparent 35%), linear-gradient(135deg, #0F172A, #111827);
    border: 1px solid #1E293B;
    border-radius: 24px;
    padding: 30px;
    margin-bottom: 22px;
}
.header-title { font-size: 42px; font-weight: 900; color: #F8FAFC; }
.header-subtitle { margin-top: 8px; color: #94A3B8; font-size: 16px; }
.metric-card {
    background: #0F172A;
    border: 1px solid #1E293B;
    border-radius: 18px;
    padding: 20px;
    min-height: 105px;
}
.metric-label { color: #94A3B8; font-size: 12px; text-transform: uppercase; letter-spacing: .05em; }
.metric-value { color: #22C55E; font-size: 22px; font-weight: 900; margin-top: 8px; }
.panel, .file-box, .chat-panel {
    background: #0F172A;
    border: 1px solid #1E293B;
    border-radius: 20px;
    padding: 22px;
    margin-bottom: 18px;
}
.chat-panel { min-height: 680px; }
.chat-title { font-size: 26px; font-weight: 900; color: #F8FAFC; }
.chat-subtitle { color: #94A3B8; margin-top: 6px; margin-bottom: 20px; }
.result-box {
    background: #000000;
    color: #22C55E;
    border: 1px solid #1E293B;
    border-radius: 14px;
    padding: 14px;
    font-family: Consolas, monospace;
    word-break: break-all;
    line-height: 1.6;
    font-size: 13px;
}
.small-text { color: #94A3B8; font-size: 14px; line-height: 1.7; }
.security-ok { color: #22C55E; font-weight: 800; }
.security-warn { color: #F59E0B; font-weight: 800; }
.security-danger { color: #EF4444; font-weight: 800; }
textarea, input {
    background: #020617 !important;
    color: #F8FAFC !important;
    border: 1px solid #334155 !important;
    border-radius: 12px !important;
}
textarea:focus, input:focus { border: 1px solid #22C55E !important; box-shadow: 0 0 0 1px #22C55E !important; }
[data-testid="InputInstructions"] { display: none !important; }
.stProgress > div > div > div > div { background-color: #22C55E !important; }
.stDownloadButton > button, .stButton > button {
    width: 100%;
    height: 44px;
    border-radius: 12px;
    background: #16A34A;
    color: white;
    border: none;
    font-weight: 800;
}
.footer { text-align: center; color: #64748B; font-size: 13px; padding: 18px; }

/* Connexion type Apple/macOS : petite carte centrée */
.login-mini-card {
    background: rgba(15, 23, 42, 0.96);
    border: 1px solid #1E293B;
    border-radius: 28px;
    padding: 34px;
    box-shadow: 0 24px 70px rgba(0,0,0,.42);
    margin-top: 12vh;
}

.login-logo {
    text-align: center;
    font-size: 56px;
    margin-bottom: 8px;
}

.login-title {
    text-align: center;
    font-size: 30px;
    font-weight: 900;
    color: #F8FAFC;
}

.login-subtitle {
    text-align: center;
    color: #94A3B8;
    margin-top: 6px;
    margin-bottom: 26px;
}

@media (max-width: 900px) {
    .block-container {
        padding-left: 12px !important;
        padding-right: 12px !important;
        padding-top: 12px !important;
        max-width: 100% !important;
    }
    .header-title { font-size: 26px !important; line-height: 1.2 !important; }
    .header-subtitle, .small-text { font-size: 13px !important; }
    .metric-card, .panel, .chat-panel, .file-box {
        padding: 14px !important;
        border-radius: 14px !important;
        margin-bottom: 12px !important;
    }
    .metric-value { font-size: 18px !important; }
    .result-box {
        font-size: 11px !important;
        padding: 10px !important;
        overflow-x: auto !important;
        word-break: break-word !important;
    }
    textarea { min-height: 100px !important; font-size: 14px !important; }
    input { font-size: 14px !important; }
    .stTabs [data-baseweb="tab-list"] { overflow-x: auto !important; flex-wrap: nowrap !important; }
    .stTabs [data-baseweb="tab"] { min-width: max-content !important; font-size: 13px !important; padding: 8px 10px !important; }
    .stButton > button, .stDownloadButton > button { min-height: 42px !important; font-size: 13px !important; }
}

</style>
""", unsafe_allow_html=True)



# =====================================================
# AUTHENTIFICATION — CARTE CENTRÉE TYPE APPLE
# =====================================================

if not st.session_state.auth:
    _left, _center, _right = st.columns([1.35, 1, 1.35])

    with _center:
        st.markdown("""
        <div class="login-mini-card">
            <div class="login-logo">🔐</div>
            <div class="login-title">CyberCrypt</div>
            <div class="login-subtitle">Enterprise Security Suite</div>
        </div>
        """, unsafe_allow_html=True)

        login_username = st.text_input(
            "Identifiant",
            placeholder="Nom d’utilisateur",
            key="login_username"
        )

        login_password = st.text_input(
            "Mot de passe",
            type="password",
            placeholder="••••••••••",
            key="login_password"
        )

        if st.button("Connexion", use_container_width=True):
            user = authenticate(login_username, login_password)
            if user:
                st.session_state.auth = True
                st.session_state.user = user
                log_audit(user["username"], "LOGIN", "auth", "Connexion utilisateur", "", "SUCCESS")
                st.rerun()
            else:
                log_audit(login_username or "unknown", "LOGIN", "auth", "Tentative de connexion échouée", "", "FAILED")
                st.error("Identifiant ou mot de passe incorrect.")

        st.markdown("""
        <div style="font-size:12px;color:#64748B;text-align:center;margin-top:18px;">
            Compte démo initial : admin / admin123
        </div>
        """, unsafe_allow_html=True)

    st.stop()


current_user = st.session_state.user
current_username = current_user["username"]
current_role = current_user["role"]

# =====================================================
# HEADER + METRICS
# =====================================================

header_left, header_right = st.columns([4, 1], gap="large")
with header_left:
    st.markdown("""
    <div class="header-card">
        <div class="header-title">🔐 CyberCrypt Enterprise Security Suite</div>
        <div class="header-subtitle">
            AES-256-GCM | PBKDF2 | SHA-256 | RSA | Signature numérique | Coffre-fort | QR sécurisé | Audit
        </div>
    </div>
    """, unsafe_allow_html=True)

with header_right:
    st.markdown(f"""
    <div class="panel">
        <b>{current_user["full_name"]}</b><br>
        <span class="small-text">{current_username} — {current_role}</span>
    </div>
    """, unsafe_allow_html=True)
    if st.button("Déconnexion"):
        log_audit(current_username, "LOGOUT", "auth", "Déconnexion utilisateur", "", "SUCCESS")
        st.session_state.auth = False
        st.session_state.user = None
        st.rerun()

records = build_audit_records()
persistent_logs = fetch_persistent_audit(500)

m1, m2, m3, m4 = st.columns(4)
with m1:
    st.markdown("""<div class="metric-card"><div class="metric-label">Messages</div><div class="metric-value">{}</div></div>""".format(count_table_for_owner("stored_messages", current_username)), unsafe_allow_html=True)
with m2:
    st.markdown("""<div class="metric-card"><div class="metric-label">Fichiers</div><div class="metric-value">{}</div></div>""".format(count_table_for_owner("stored_files", current_username)), unsafe_allow_html=True)
with m3:
    st.markdown("""<div class="metric-card"><div class="metric-label">Coffre-fort</div><div class="metric-value">{}</div></div>""".format(count_table_for_owner("stored_vault", current_username)), unsafe_allow_html=True)
with m4:
    st.markdown("""<div class="metric-card"><div class="metric-label">Statut</div><div class="metric-value">Enterprise</div></div>""", unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)


# =====================================================
# ONGLETS
# =====================================================

tab_labels = [
    "📊 Dashboard",
    "💬 Conversation sécurisée",
    "📁 Fichiers sécurisés",
    "🛡️ SOC — Centre de sécurité",
    "🔒 Coffre-fort",
    "✍️ Signature numérique",
    "📱 QR sécurisé",
    "📄 Audit & rapports",
    "🎤 Mode présentation",
    "ℹ️ Documentation",
]

if current_role == "admin":
    tab_labels.insert(8, "👥 Utilisateurs")

tab_objects = st.tabs(tab_labels)
tab_map = dict(zip(tab_labels, tab_objects))

tab_dashboard = tab_map["📊 Dashboard"]
tab_chat = tab_map["💬 Conversation sécurisée"]
tab_files = tab_map["📁 Fichiers sécurisés"]
tab_soc = tab_map["🛡️ SOC — Centre de sécurité"]
tab_vault = tab_map["🔒 Coffre-fort"]
tab_signature = tab_map["✍️ Signature numérique"]
tab_qr = tab_map["📱 QR sécurisé"]
tab_audit = tab_map["📄 Audit & rapports"]
tab_presentation = tab_map["🎤 Mode présentation"]
tab_doc = tab_map["ℹ️ Documentation"]
tab_users = tab_map.get("👥 Utilisateurs")


# =====================================================
# DASHBOARD
# =====================================================

with tab_dashboard:
    st.markdown("""
    <div class="panel">
        <h3>📊 Tableau de bord</h3>
        <div class="small-text">Vue synthétique des opérations de sécurité réalisées dans l'application.</div>
    </div>
    """, unsafe_allow_html=True)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Messages traités", count_table_for_owner("stored_messages", current_username))
    c2.metric("Fichiers sécurisés", count_table_for_owner("stored_files", current_username))
    c3.metric("Secrets coffre-fort", count_table_for_owner("stored_vault", current_username))
    c4.metric("Événements audit", len(records))
    st.markdown("### Capacités actives")
    st.table({
        "Module": ["Messages", "Fichiers", "Centre de sécurité", "Coffre-fort", "Signature", "QR", "Audit"],
        "Fonction": ["AES-256-GCM", "PDF/Image/DOCX/TXT", "César/RSA/SHA/Password", "Secrets chiffrés", "RSA-PSS", "Token chiffré", "PDF/JSON/CSV"],
        "Statut": ["Actif", "Actif", "Actif", "Actif", "Actif", "Actif", "Actif"],
    })


# =====================================================
# CHAT
# =====================================================

with tab_chat:
    left, right = st.columns([2.5, 1], gap="large")
    with left:
        st.markdown("""
        <div class="chat-panel">
            <div class="chat-title">Conversation sécurisée</div>
            <div class="chat-subtitle">Entrez une clé secrète, puis tapez un message. Le chiffrement ou le déchiffrement se fait automatiquement.</div>
        """, unsafe_allow_html=True)
        password = st.text_input("Clé secrète", type="password", placeholder="Exemple : MonMotDePasse@2026", key="chat_password")
        score, level = password_strength(password)
        st.progress(score)
        st.caption(f"Niveau de la clé : {level}")
        user_input = st.text_area("Votre message / message à déchiffrer", height=120, placeholder="Tapez un message clair ou collez un message chiffré CyberCrypt...", key="chat_input")
        output = ""
        operation = ""
        hash_value = ""
        if user_input.strip() and password.strip():
            current_key = user_input + password
            if current_key != st.session_state.last_input:
                if is_encrypted_message(user_input):
                    operation = "Déchiffrement automatique"
                    decrypted = decrypt_message(user_input, password)
                    if decrypted in ["ERROR", "FORMAT_INVALID"]:
                        output = "Impossible de déchiffrer : clé incorrecte ou message modifié."
                        hash_value = ""
                    else:
                        output = decrypted
                        hash_value = sha256_text(decrypted)
                else:
                    operation = "Chiffrement automatique"
                    output = encrypt_message(user_input, password)
                    hash_value = sha256_text(user_input)
                st.session_state.messages = [
                    {"role": "user", "content": user_input, "time": datetime.now().strftime("%H:%M:%S")},
                    {"role": "assistant", "operation": operation, "content": output, "hash": hash_value, "time": datetime.now().strftime("%H:%M:%S")},
                ]
                st.session_state.last_input = current_key
                st.session_state.last_result = output
                log_audit(current_username, operation.upper().replace(" ", "_"), "message", "Traitement message", hash_value, "SUCCESS" if hash_value else "FAILED")
                store_message(current_username, operation, user_input, output, hash_value, "SUCCESS" if hash_value else "FAILED")
        elif user_input.strip() and not password.strip():
            st.warning("Entrez une clé secrète pour activer le traitement automatique.")
        st.divider()
        if not st.session_state.messages:
            with st.chat_message("assistant"):
                st.write("Conversation prête. Entrez une clé secrète puis écrivez un message.")
        else:
            for msg in st.session_state.messages:
                if msg["role"] == "user":
                    with st.chat_message("user"):
                        st.write(msg["content"])
                        st.caption(msg["time"])
                if msg["role"] == "assistant":
                    with st.chat_message("assistant"):
                        st.caption(f"CyberCrypt — {msg['operation']} | {msg['time']}")
                        st.markdown(f"<div class='result-box'>{msg['content']}</div>", unsafe_allow_html=True)
                        copy_button(msg["content"], "📋 Copier le résultat")
                        if msg["hash"]:
                            st.write("Empreinte SHA-256")
                            st.markdown(f"<div class='result-box'>{msg['hash']}</div>", unsafe_allow_html=True)
                            copy_button(msg["hash"], "📋 Copier l’empreinte SHA-256")
        if st.session_state.last_result:
            st.download_button("⬇️ Télécharger le résultat", st.session_state.last_result, file_name="cybercrypt_result.txt", mime="text/plain")
        st.markdown("</div>", unsafe_allow_html=True)
    with right:
        st.markdown("""
        <div class="panel"><h3>Fonctionnement</h3><div class="small-text">
        1. Entrez une clé secrète.<br><br>2. Tapez un message clair.<br><br>3. CyberCrypt chiffre automatiquement.<br><br>4. Copiez le résultat pour le partager ou le déchiffrer.
        </div></div>
        """, unsafe_allow_html=True)


# =====================================================
# FICHIERS
# =====================================================

with tab_files:
    st.markdown("""<div class="panel"><h3>📁 Sécurisation de fichiers</h3><div class="small-text">Chiffrez ou déchiffrez localement des fichiers PDF, images, TXT ou DOCX. Le fichier chiffré est exporté au format <b>.cyber</b>.</div></div>""", unsafe_allow_html=True)
    file_col1, file_col2 = st.columns(2, gap="large")
    with file_col1:
        st.markdown("<div class='file-box'>", unsafe_allow_html=True)
        st.subheader("🔒 Chiffrer un fichier")
        file_to_encrypt = st.file_uploader("Importer un fichier à sécuriser", type=["pdf", "png", "jpg", "jpeg", "txt", "docx"], key="file_encrypt")
        file_password = st.text_input("Clé secrète du fichier", type="password", key="file_encrypt_password")
        if file_to_encrypt and file_password:
            file_bytes = file_to_encrypt.read()
            encrypted_file = encrypt_file(file_bytes, file_password, file_to_encrypt.name)
            original_hash = sha256_file(file_bytes)
            st.success("Fichier chiffré avec succès.")
            st.write("Empreinte SHA-256 du fichier original")
            st.markdown(f"<div class='result-box'>{original_hash}</div>", unsafe_allow_html=True)
            copy_button(original_hash, "📋 Copier l’empreinte du fichier")
            st.download_button("⬇️ Télécharger le fichier sécurisé", encrypted_file, file_name=file_to_encrypt.name + ".cyber", mime="application/octet-stream")
            st.session_state.file_history.insert(0, {"time": datetime.now().strftime("%H:%M:%S"), "operation": "Chiffrement fichier", "filename": file_to_encrypt.name, "hash": original_hash[:24] + "..."})
            log_audit(current_username, "ENCRYPT_FILE", "file", file_to_encrypt.name, original_hash, "SUCCESS")
            store_file_event(current_username, "Chiffrement fichier", file_to_encrypt.name, original_hash, "SUCCESS")
        st.markdown("</div>", unsafe_allow_html=True)
    with file_col2:
        st.markdown("<div class='file-box'>", unsafe_allow_html=True)
        st.subheader("🔓 Déchiffrer un fichier")
        file_to_decrypt = st.file_uploader("Importer un fichier .cyber", type=["cyber"], key="file_decrypt")
        decrypt_file_password = st.text_input("Clé secrète de déchiffrement", type="password", key="file_decrypt_password")
        if file_to_decrypt and decrypt_file_password:
            encrypted_bytes = file_to_decrypt.read()
            original_name, decrypted_bytes, status = decrypt_file(encrypted_bytes, decrypt_file_password)
            if status == "OK":
                restored_hash = sha256_file(decrypted_bytes)
                st.success("Fichier déchiffré avec succès.")
                st.write("Empreinte SHA-256 du fichier restauré")
                st.markdown(f"<div class='result-box'>{restored_hash}</div>", unsafe_allow_html=True)
                copy_button(restored_hash, "📋 Copier l’empreinte restaurée")
                st.download_button("⬇️ Télécharger le fichier restauré", decrypted_bytes, file_name=original_name, mime="application/octet-stream")
                st.session_state.file_history.insert(0, {"time": datetime.now().strftime("%H:%M:%S"), "operation": "Déchiffrement fichier", "filename": original_name, "hash": restored_hash[:24] + "..."})
                log_audit(current_username, "DECRYPT_FILE", "file", original_name, restored_hash, "SUCCESS")
                store_file_event(current_username, "Déchiffrement fichier", original_name, restored_hash, "SUCCESS")
            else:
                st.error("Impossible de déchiffrer : clé incorrecte ou fichier modifié.")
        st.markdown("</div>", unsafe_allow_html=True)


# =====================================================
# SOC — CENTRE DE SÉCURITÉ
# =====================================================

with tab_soc:
    st.markdown("""<div class="panel"><h3>🛡️ SOC — Centre de sécurité</h3><div class="small-text">Outils professionnels : César, RSA, SHA-256, générateur et analyseur de mot de passe, simulateur d’attaque.</div></div>""", unsafe_allow_html=True)
    tool1, tool2 = st.columns(2, gap="large")
    with tool1:
        st.subheader("🔁 Chiffrement de César")
        caesar_text = st.text_area("Texte pour César", height=100, key="caesar_text")
        caesar_shift = st.slider("Décalage", min_value=1, max_value=25, value=3)
        if caesar_text:
            caesar_encrypted = caesar_encrypt(caesar_text, caesar_shift)
            caesar_decrypted = caesar_decrypt(caesar_encrypted, caesar_shift)
            st.write("Résultat chiffré")
            st.markdown(f"<div class='result-box'>{caesar_encrypted}</div>", unsafe_allow_html=True)
            copy_button(caesar_encrypted, "📋 Copier César chiffré")
            st.write("Résultat déchiffré")
            st.markdown(f"<div class='result-box'>{caesar_decrypted}</div>", unsafe_allow_html=True)
    with tool2:
        st.subheader("🔐 Générateur / Analyseur de mot de passe")
        pwd_length = st.slider("Longueur", min_value=12, max_value=40, value=18)
        if st.button("Générer un mot de passe fort"):
            st.session_state.generated_password = generate_password(pwd_length)
        if st.session_state.generated_password:
            st.markdown(f"<div class='result-box'>{st.session_state.generated_password}</div>", unsafe_allow_html=True)
            copy_button(st.session_state.generated_password, "📋 Copier le mot de passe")
        pwd_to_check = st.text_input("Analyser un mot de passe", type="password", key="pwd_analyzer")
        if pwd_to_check:
            score, label = password_strength(pwd_to_check)
            st.progress(score)
            st.write(f"Force : **{score}/100 — {label}**")
            st.write(f"Temps estimé de cassage : **{crack_time_estimate(pwd_to_check)}**")
    st.divider()
    rsa_col1, rsa_col2 = st.columns(2, gap="large")
    with rsa_col1:
        st.subheader("🔑 RSA — Chiffrement asymétrique")
        rsa_text = st.text_area("Texte à chiffrer avec RSA", height=100, key="rsa_text")
        if rsa_text:
            try:
                rsa_result = rsa_encrypt_text(rsa_text, st.session_state.rsa_public_key)
                st.markdown(f"<div class='result-box'>{rsa_result}</div>", unsafe_allow_html=True)
                copy_button(rsa_result, "📋 Copier RSA chiffré")
            except Exception:
                st.error("RSA ne peut chiffrer que des messages courts.")
    with rsa_col2:
        st.subheader("🔓 RSA — Déchiffrement")
        rsa_token = st.text_area("Message RSA chiffré", height=100, key="rsa_token")
        if rsa_token:
            rsa_decrypted = rsa_decrypt_text(rsa_token, st.session_state.rsa_private_key)
            st.markdown(f"<div class='result-box'>{rsa_decrypted}</div>", unsafe_allow_html=True)
            copy_button(rsa_decrypted, "📋 Copier RSA déchiffré")
    st.divider()
    st.subheader("🧾 Empreinte SHA-256")
    sha_text = st.text_area("Texte à analyser avec SHA-256", height=100, key="sha_text")
    if sha_text:
        sha_result = sha256_text(sha_text)
        st.markdown(f"<div class='result-box'>{sha_result}</div>", unsafe_allow_html=True)
        copy_button(sha_result, "📋 Copier SHA-256")
    st.divider()
    st.subheader("⚔️ Simulateur d’attaque")
    st.table({
        "Méthode": ["César", "SHA-256", "RSA-2048", "AES-256-GCM"],
        "Résistance brute force": ["Très faible", "Non réversible", "Élevée", "Très élevée"],
        "Risque pédagogique": ["Cassable rapidement", "Collision théorique", "Dépend des clés", "Dépend du mot de passe"],
        "Usage recommandé": ["Démonstration", "Intégrité", "Signature/échange", "Confidentialité"],
    })


# =====================================================
# VAULT — COFFRE-FORT
# =====================================================

with tab_vault:
    st.markdown("""<div class="panel"><h3>🔒 Coffre-fort sécurisé</h3><div class="small-text">Stockage local de notes sensibles, clés API, tokens ou mots de passe. Chaque secret est chiffré avec AES-256-GCM.</div></div>""", unsafe_allow_html=True)
    col1, col2 = st.columns(2, gap="large")
    with col1:
        st.subheader("Ajouter un secret")
        vault_title = st.text_input("Titre", key="vault_title", placeholder="Ex : API Key OpenAI")
        vault_category = st.selectbox("Catégorie", ["Mot de passe", "Clé API", "Token", "Note confidentielle", "Autre"], key="vault_category")
        vault_secret = st.text_area("Secret", height=120, key="vault_secret")
        vault_password = st.text_input("Clé maître du coffre-fort", type="password", key="vault_password")
        if st.button("🔒 Chiffrer et ajouter au coffre-fort"):
            if vault_title and vault_secret and vault_password:
                item = {"title": vault_title, "category": vault_category, "secret": vault_secret, "created_at": datetime.now().strftime("%d/%m/%Y %H:%M:%S")}
                token = encrypt_vault_item(item, vault_password)
                item_hash = sha256_text(vault_secret)
                st.session_state.vault_items.insert(0, {"title": vault_title, "category": vault_category, "token": token, "hash": item_hash[:24] + "...", "created_at": item["created_at"]})
                st.session_state.vault_history.insert(0, {"time": datetime.now().strftime("%H:%M:%S"), "operation": "Ajout coffre-fort", "title": vault_title, "hash": item_hash[:24] + "..."})
                log_audit(current_username, "VAULT_CREATE", "vault", vault_title, item_hash, "SUCCESS")
                store_vault_item(current_username, vault_title, vault_category, token, item_hash[:24] + "...")
                st.success("Secret ajouté au coffre-fort.")
            else:
                st.error("Titre, secret et clé maître sont obligatoires.")
    with col2:
        st.subheader("Consulter un secret")
        if st.session_state.vault_items:
            selected = st.selectbox("Secret", list(range(count_table_for_owner("stored_vault", current_username))), format_func=lambda i: f"{st.session_state.vault_items[i]['title']} — {st.session_state.vault_items[i]['category']}")
            read_password = st.text_input("Clé maître pour déchiffrer", type="password", key="vault_read_password")
            if read_password:
                item = st.session_state.vault_items[selected]
                decrypted = decrypt_vault_item(item["token"], read_password)
                if decrypted:
                    st.success("Secret déchiffré.")
                    st.write(f"Catégorie : {decrypted['category']}")
                    st.markdown(f"<div class='result-box'>{decrypted['secret']}</div>", unsafe_allow_html=True)
                    copy_button(decrypted["secret"], "📋 Copier le secret")
                else:
                    st.error("Clé maître incorrecte.")
            st.download_button("⬇️ Export coffre-fort chiffré", json.dumps(st.session_state.vault_items, ensure_ascii=False, indent=2), file_name="cybercrypt_vault_export.json", mime="application/json")
        else:
            st.info("Aucun secret enregistré pour le moment.")


# =====================================================
# SIGNATURE NUMÉRIQUE
# =====================================================

with tab_signature:
    st.markdown("""<div class="panel"><h3>✍️ Signature numérique</h3><div class="small-text">Signez un message ou un fichier avec RSA-PSS/SHA-256, puis vérifiez son intégrité.</div></div>""", unsafe_allow_html=True)
    sign_col, verify_col = st.columns(2, gap="large")
    with sign_col:
        st.subheader("Signer")
        sign_text = st.text_area("Texte à signer", height=120, key="sign_text")
        sign_file = st.file_uploader("Ou importer un fichier à signer", key="sign_file")
        data_to_sign = None
        if sign_file:
            data_to_sign = sign_file.read()
        elif sign_text:
            data_to_sign = sign_text.encode("utf-8")
        if data_to_sign and st.button("✍️ Générer la signature"):
            sig = sign_data(data_to_sign, st.session_state.rsa_private_key)
            digest = sha256_file(data_to_sign)
            st.session_state.signature = sig
            st.session_state.signature_hash = digest
            st.session_state.signed_data = base64.b64encode(data_to_sign).decode("utf-8")
            log_audit(current_username, "SIGN_DATA", "signature", "Signature générée", digest, "SUCCESS")
            store_signature(current_username, digest, sig, "SUCCESS")
            st.success("Signature générée.")
        if st.session_state.signature:
            st.write("Signature")
            st.markdown(f"<div class='result-box'>{st.session_state.signature}</div>", unsafe_allow_html=True)
            copy_button(st.session_state.signature, "📋 Copier la signature")
            st.write("Empreinte SHA-256")
            st.markdown(f"<div class='result-box'>{st.session_state.signature_hash}</div>", unsafe_allow_html=True)
    with verify_col:
        st.subheader("Vérifier")
        verify_text = st.text_area("Texte à vérifier", height=120, key="verify_text")
        verify_file = st.file_uploader("Ou importer un fichier à vérifier", key="verify_file")
        verify_sig = st.text_area("Signature à vérifier", height=120, key="verify_sig")
        data_to_verify = None
        if verify_file:
            data_to_verify = verify_file.read()
        elif verify_text:
            data_to_verify = verify_text.encode("utf-8")
        if data_to_verify and verify_sig:
            if verify_signature(data_to_verify, verify_sig, st.session_state.rsa_public_key):
                st.success("Signature valide : le contenu n’a pas été modifié.")
            else:
                st.error("Signature invalide : contenu modifié ou mauvaise signature.")


# =====================================================
# QR SÉCURISÉ
# =====================================================

with tab_qr:
    st.markdown("""<div class="panel"><h3>📱 QR sécurisé</h3><div class="small-text">Transformez un message chiffré en QR Code. Le QR contient uniquement le message chiffré, pas la clé secrète.</div></div>""", unsafe_allow_html=True)
    if not QR_AVAILABLE:
        st.warning("Module QR manquant. Installe-le avec : pip install qrcode[pil]")
    qr_col1, qr_col2 = st.columns(2, gap="large")
    with qr_col1:
        qr_message = st.text_area("Message à sécuriser en QR", height=120, key="qr_message")
        qr_password = st.text_input("Clé secrète QR", type="password", key="qr_password")
        if qr_message and qr_password:
            qr_token = encrypt_message(qr_message, qr_password)
            qr_hash = sha256_text(qr_message)
            qr_unique = qr_message + qr_password
            if st.session_state.get("last_qr_saved") != qr_unique:
                store_qr(current_username, qr_token, qr_hash, "SUCCESS")
                log_audit(current_username, "CREATE_QR", "qr", "QR sécurisé généré", qr_hash, "SUCCESS")
                st.session_state.last_qr_saved = qr_unique
            st.write("Message chiffré pour QR")
            st.markdown(f"<div class='result-box'>{qr_token}</div>", unsafe_allow_html=True)
            copy_button(qr_token, "📋 Copier le token QR")
            if QR_AVAILABLE:
                img_bytes = make_qr_image(qr_token)
                if img_bytes:
                    st.image(img_bytes, caption="QR Code sécurisé", width=260)
                    st.download_button("⬇️ Télécharger le QR", img_bytes, file_name="cybercrypt_qr.png", mime="image/png")
    with qr_col2:
        qr_token_input = st.text_area("Coller un token QR chiffré", height=120, key="qr_token_input")
        qr_password_input = st.text_input("Clé secrète de lecture", type="password", key="qr_password_input")
        if qr_token_input and qr_password_input:
            result = decrypt_message(qr_token_input, qr_password_input)
            if result == "ERROR":
                st.error("Impossible de lire le QR : clé incorrecte ou contenu modifié.")
            else:
                st.success("QR déchiffré.")
                st.markdown(f"<div class='result-box'>{result}</div>", unsafe_allow_html=True)
                copy_button(result, "📋 Copier le message QR")


# =====================================================
# AUDIT & RAPPORTS
# =====================================================

with tab_audit:
    records = build_audit_records()
    persistent_logs = fetch_persistent_audit(500)

    st.markdown("""<div class="panel"><h3>📄 Audit & rapports</h3><div class="small-text">Exportez le journal d’audit applicatif et le journal persistant des utilisateurs.</div></div>""", unsafe_allow_html=True)

    audit_tab1, audit_tab2 = st.tabs(["Journal applicatif", "Journal persistant"])

    with audit_tab1:
        if records:
            st.dataframe(records, use_container_width=True)
        else:
            st.info("Aucun événement d’audit applicatif pour le moment.")

        col_json, col_csv, col_pdf = st.columns(3)
        with col_json:
            st.download_button("⬇️ Export JSON", export_json_bytes(records), file_name="cybercrypt_audit.json", mime="application/json")
        with col_csv:
            st.download_button("⬇️ Export CSV", export_csv_bytes(records), file_name="cybercrypt_audit.csv", mime="text/csv")
        with col_pdf:
            pdf = generate_pdf_report(records)
            if pdf:
                st.download_button("⬇️ Rapport PDF", pdf, file_name="rapport_cybercrypt_enterprise.pdf", mime="application/pdf")
            else:
                st.warning("PDF indisponible. Installe : pip install reportlab")

    with audit_tab2:
        if persistent_logs:
            st.dataframe(persistent_logs, use_container_width=True)
        else:
            st.info("Aucun événement persistant pour le moment.")

        p1, p2, p3 = st.columns(3)
        with p1:
            st.download_button(
                "⬇️ Export persistant JSON",
                json.dumps(persistent_logs, ensure_ascii=False, indent=2),
                file_name="audit_persistant.json",
                mime="application/json"
            )
        with p2:
            st.download_button(
                "⬇️ Export persistant CSV",
                export_persistent_audit_csv(persistent_logs),
                file_name="audit_persistant.csv",
                mime="text/csv"
            )
        with p3:
            audit_pdf = generate_persistent_audit_pdf(persistent_logs)
            if audit_pdf:
                st.download_button(
                    "⬇️ Rapport persistant PDF",
                    audit_pdf,
                    file_name="rapport_audit_persistant.pdf",
                    mime="application/pdf"
                )
            else:
                st.warning("PDF indisponible. Installe : pip install reportlab")


# =====================================================
# UTILISATEURS
# =====================================================

if tab_users is not None:
    with tab_users:
        st.markdown("""<div class="panel"><h3>👥 Gestion des utilisateurs</h3><div class="small-text">Créer, activer ou désactiver des comptes. Onglet réservé aux administrateurs.</div></div>""", unsafe_allow_html=True)

        u1, u2 = st.columns(2, gap="large")

        with u1:
            st.subheader("Créer un utilisateur")
            new_username = st.text_input("Identifiant", key="new_username")
            new_full_name = st.text_input("Nom complet", key="new_full_name")
            new_role = st.selectbox("Rôle", ["admin", "analyst", "viewer"], key="new_role")
            new_password = st.text_input("Mot de passe initial", type="password", key="new_password")

            if st.button("Créer l’utilisateur"):
                if new_username and new_full_name and new_password:
                    try:
                        create_user(new_username, new_full_name, new_password, new_role)
                        log_audit(current_username, "CREATE_USER", "user", new_username, "", "SUCCESS")
                        st.success("Utilisateur créé.")
                    except Exception as e:
                        st.error(f"Erreur : {e}")
                else:
                    st.error("Tous les champs sont obligatoires.")

        with u2:
            st.subheader("Liste des utilisateurs")
            users = fetch_users()
            st.dataframe(users, use_container_width=True)

            selected_id = st.number_input("ID utilisateur à modifier", min_value=1, step=1)
            b1, b2 = st.columns(2)

            with b1:
                if st.button("Désactiver"):
                    set_user_status(int(selected_id), 0)
                    log_audit(current_username, "DISABLE_USER", "user", str(selected_id), "", "SUCCESS")
                    st.success("Utilisateur désactivé.")

            with b2:
                if st.button("Activer"):
                    set_user_status(int(selected_id), 1)
                    log_audit(current_username, "ENABLE_USER", "user", str(selected_id), "", "SUCCESS")
                    st.success("Utilisateur activé.")


# =====================================================
# MODE PRÉSENTATION
# =====================================================

with tab_presentation:
    st.markdown("""<div class="panel"><h3>🎤 Mode présentation</h3><div class="small-text">Résumé prêt à expliquer en cours ou en démonstration.</div></div>""", unsafe_allow_html=True)
    st.markdown("""
    ### Pitch court
    J’ai développé **CyberCrypt Enterprise Security Suite**, une application locale de cryptographie.
    Elle permet de chiffrer des messages et fichiers avec **AES-256-GCM**, de générer des empreintes **SHA-256**,
    d’illustrer **RSA**, de signer numériquement des contenus et de stocker des secrets dans un coffre-fort chiffré.

    ### Schéma de fonctionnement
    ```text
    Message / Fichier / Secret
              ↓
       Mot de passe utilisateur
              ↓
       PBKDF2 → clé AES 256 bits
              ↓
       AES-GCM → contenu chiffré
              ↓
       SHA-256 → preuve d’intégrité
    ```

    ### Points forts à présenter
    - Confidentialité : seul le détenteur de la clé peut déchiffrer.
    - Intégrité : AES-GCM détecte les modifications.
    - Traçabilité : audit JSON/CSV/PDF.
    - Pédagogie : comparaison César, RSA, SHA-256, AES.
    - Cas professionnel : RH, finance, audit, juridique, SI.
    """)


# =====================================================
# DOCUMENTATION
# =====================================================

with tab_doc:
    st.markdown("""
    <div class="panel">
        <h3>ℹ️ Documentation</h3>
        <div class="small-text">
            CyberCrypt Enterprise est une application pédagogique et démonstrative de cryptographie.
            Elle fonctionne localement et ne transmet pas les données à un serveur externe.
        </div>
    </div>
    """, unsafe_allow_html=True)
    st.markdown("""
    ### Modules inclus
    - **AES-256-GCM** : chiffrement moderne des messages, fichiers et secrets.
    - **PBKDF2** : transformation d’un mot de passe en clé cryptographique.
    - **SHA-256** : empreinte d’intégrité.
    - **RSA** : chiffrement asymétrique et signature numérique.
    - **César** : comparaison historique pédagogique.
    - **Coffre-fort** : stockage local de secrets chiffrés.
    - **QR sécurisé** : partage d’un message chiffré sous forme de QR.
    - **Audit** : exports JSON, CSV et PDF.

    ### Dépendances recommandées
    ```powershell
    pip install streamlit cryptography qrcode[pil] reportlab
    ```
    """)


st.markdown("""
<div class="footer">
    CyberCrypt Enterprise Security Suite — AES-256-GCM | PBKDF2 | SHA-256 | RSA | Vault | Signature | QR | Audit
</div>
""", unsafe_allow_html=True)
