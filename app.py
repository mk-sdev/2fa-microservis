from flask import Flask, request, jsonify
import pyotp
import jwt
import datetime
import qrcode
import io
import base64
import psycopg2
from flask_cors import CORS
from dotenv import load_dotenv
import os
import redis
from cryptography.fernet import Fernet
import string
import random
import secrets

app = Flask(__name__)

r = redis.Redis(host="localhost", port=6379, db=0, decode_responses=True)

CORS(
    app,
    supports_credentials=True,  # allows sending cookies
    origins=[
        "http://localhost:4200",  
        "http://localhost:4201",  
    ]
)


load_dotenv()

JWT_ACCESS_SECRET = os.getenv("JWT_ACCESS_SECRET")
JWT_REFRESH_SECRET = os.getenv("JWT_REFRESH_SECRET")
JWT_2FA_SECRET = os.getenv("JWT_2FA_SECRET")
DATABASE_URL = os.getenv("DATABASE_URL")
ISSUER = "IAM System"
FERNET_KEY = os.getenv("TOTP_ENCRYPTION_KEY")

fernet = Fernet(FERNET_KEY)

def encrypt_secret(secret: str) -> str:
    return fernet.encrypt(secret.encode()).decode()

def decrypt_secret(encrypted_secret: str) -> str:
    return fernet.decrypt(encrypted_secret.encode()).decode()



def generate_backup_codes(n=10, length=8):
    """Generates a list of n random backup codes, each of specified length"""
    alphabet = string.ascii_uppercase + string.digits
    return [''.join(secrets.choice(alphabet) for _ in range(length)) for _ in range(n)]

def store_backup_codes(user_id, codes):
    """Stores the list of backup codes in the backup_codes table, each as a separate record"""
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()

    for code in codes:
        encrypted = encrypt_secret(code)
        cur.execute(
            "INSERT INTO backup_codes (user_id, code) VALUES (%s, %s)",
            (user_id, encrypted)
        )

    conn.commit()
    cur.close()
    conn.close()

def get_user_id_from_token():
    '''
    Helper fucntion to extract user ID from either access token or 2fa token in cookies
    '''
    token = request.cookies.get("access_token") or request.cookies.get("2fa_token")
    if not token:
        return None

    try:
        if request.cookies.get("2fa_token") == token:
            payload = jwt.decode(token, JWT_2FA_SECRET, algorithms=["HS256"])
        else:
            payload = jwt.decode(token, JWT_ACCESS_SECRET, algorithms=["HS256"])
        return payload.get("sub")
    except Exception:
        return None

@app.route("/enable-2fa", methods=["PATCH"])
def enable_2fa():
    '''
    Generates a temporary secret for 2FA setup, creates a provisioning URI, and returns a QR code for the user to scan 
    The temporary secret is stored in the database until the user confirms 2FA setup
    '''
    user_id = get_user_id_from_token()

    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    temp_secret = pyotp.random_base32()
    encrypted_temp_secret = encrypt_secret(temp_secret)

    totp = pyotp.TOTP(temp_secret)

    uri = totp.provisioning_uri(
        name=str(user_id),
        issuer_name=ISSUER
    )

    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()

    cur.execute("""
        UPDATE users
        SET otp_temp_secret = %s
        WHERE _id = %s
    """, (encrypted_temp_secret, user_id))

    conn.commit()
    cur.close()
    conn.close()

    # QR
    qr = qrcode.make(uri)
    buffer = io.BytesIO()
    qr.save(buffer, format="PNG")

    qr_base64 = base64.b64encode(buffer.getvalue()).decode()

    return jsonify({
        "qr_base64": qr_base64
    })


@app.route("/confirm-2fa", methods=["POST"])
def confirm_2fa():
    '''
    Verifies the 2FA code entered by the user against the temporary secret stored in the database
    If the code is valid, the temporary secret is promoted to the permanent otp_secret, and 2FA is enabled for the user
    '''
    user_id = get_user_id_from_token()
    code = request.json.get("code")

    if not user_id or not code:
        return jsonify({"error": "Invalid request"}), 400

    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()

    cur.execute("""
        SELECT otp_temp_secret FROM users WHERE _id = %s
    """, (user_id,))

    row = cur.fetchone()

    if not row or not row[0]:
        return jsonify({"error": "2FA not initialized"}), 400

    temp_secret = decrypt_secret(row[0])

    totp = pyotp.TOTP(temp_secret)

    if not totp.verify(code, valid_window=1):
        return jsonify({"error": "Invalid code"}), 401

    encrypted_secret = encrypt_secret(temp_secret)

    cur.execute("""
        UPDATE users
        SET otp_secret = %s,
            otp_temp_secret = NULL,
            is_2fa_enabled = TRUE
        WHERE _id = %s
    """, (encrypted_secret, user_id))

    conn.commit()
    cur.close()
    conn.close()

    # Po udanym potwierdzeniu 2FA
    backup_codes = generate_backup_codes()
    store_backup_codes(user_id, backup_codes)

    return jsonify({
        "message": "2FA enabled",
        "backup_codes": backup_codes  # shown only once to the user
    })



@app.route("/disable-2fa", methods=["PATCH"])
def disable_2fa():
    '''
    Disables 2FA for the user by clearing otp_secret, otp_temp_secret,
    is_2fa_enabled, and deleting all backup codes for the user
    '''
    user_id = get_user_id_from_token()
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    try:
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()

        # remove backup codes
        cur.execute("""
            DELETE FROM backup_codes
            WHERE user_id = %s
        """, (user_id,))

        # turn off 2FA and clear secrets
        cur.execute("""
            UPDATE users
            SET otp_secret = NULL,
                otp_temp_secret = NULL,
                is_2fa_enabled = FALSE
            WHERE _id = %s
        """, (user_id,))

        conn.commit()
        cur.close()
        conn.close()

        return jsonify({"message": "2FA disabled and backup codes removed successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/is-2fa-enabled", methods=["GET"])
def is_2fa_enabled():
    '''
    Checks if 2FA is enabled for the user by querying the is_2fa_enabled field in the database
    '''
    user_id = get_user_id_from_token()
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()

    cur.execute("""
        SELECT is_2fa_enabled
        FROM users
        WHERE _id = %s
    """, (user_id,))

    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row:
        return jsonify({"error": "User not found"}), 404

    return jsonify({"isTwoFactorEnabled": row[0]})


def is_rate_limited(user_id, limit=5):
    key = f"2fa:{user_id}"
    attempts = r.get(key)
    return attempts is not None and int(attempts) >= limit

@app.route("/verify-2fa", methods=["PATCH"])
def verify_2fa():
    '''
    Verifies the 2FA code entered by the user against the otp_secret stored in the database
    If the code is valid, generates access and refresh tokens, and returns them in httpOnly cookies
    '''
    user_id = get_user_id_from_token()

    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    if is_rate_limited(user_id):
        return jsonify({"error": "Too many attempts. Try again later."}), 429

    code = request.json.get("code")
    if not code:
        return jsonify({"error": "Missing 2FA code"}), 400

    try:
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()

        cur.execute("SELECT otp_secret FROM users WHERE _id = %s", (user_id,))
        row = cur.fetchone()
        cur.close()
        conn.close()

        if not row or not row[0]:
            return jsonify({"error": "2FA not enabled"}), 400

        secret = decrypt_secret(row[0])
        totp = pyotp.TOTP(secret)

        key = f"2fa:{user_id}"

        if not totp.verify(code, valid_window=1):
            # increment attempt counter in Redis and set expiration if it's the first attempt
            attempts = r.incr(key)
            if attempts == 1:
                r.expire(key, 300)  # 5 min
            return jsonify({"error": "Invalid code"}), 401

        access_payload = {
            "sub": user_id,
            "2fa": True,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
        }
        access_token = jwt.encode(access_payload, JWT_ACCESS_SECRET, algorithm="HS256")

        refresh_payload = {
            "sub": user_id,
            "2fa": True,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }
        refresh_token = jwt.encode(refresh_payload, JWT_REFRESH_SECRET, algorithm="HS256")

        response = jsonify({"message": "2FA verified"})

        response.set_cookie(
            "access_token", access_token,
            httponly=True,
            secure=False, # change to True in production
            samesite="lax",
            max_age=15*60  # 15 minutes
        )
        response.set_cookie(
            "refresh_token", refresh_token,
            httponly=True,
            secure=False, # change to True in production
            samesite="lax",
            max_age=60*60  # 1 hour
        )

        r.delete(f"2fa:{user_id}")  # reset attempt counter on successful verification
        return response

    except Exception as e:
        return jsonify({"error": str(e)}), 500

from flask import Flask, request, jsonify

@app.route("/verify-backup-code", methods=["DELETE"])
def verify_backup_code():
    '''Verifies the backup code entered by the user against the codes stored in the database'''
    user_id = get_user_id_from_token()
    code = request.json.get("code")

    if not user_id or not code:
        return jsonify({"error": "Invalid request"}), 400

    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()

    # get all backup codes for the user
    cur.execute("SELECT id, code FROM backup_codes WHERE user_id = %s", (user_id,))
    rows = cur.fetchall()

    if not rows:
        cur.close()
        conn.close()
        return jsonify({"error": "No backup codes available"}), 400

    matched_id = None
    for row in rows:
        backup_id, encrypted_code = row
        if decrypt_secret(encrypted_code) == code:
            matched_id = backup_id
            break

    if not matched_id:
        cur.close()
        conn.close()
        return jsonify({"error": "Invalid backup code"}), 401

    # delete the used backup code
    cur.execute("DELETE FROM backup_codes WHERE id = %s", (matched_id,))
    conn.commit()
    cur.close()
    conn.close()

    access_payload = {
        "sub": user_id,
        "2fa": True,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
    }
    access_token = jwt.encode(access_payload, JWT_ACCESS_SECRET, algorithm="HS256")

    refresh_payload = {
        "sub": user_id,
        "2fa": True,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    refresh_token = jwt.encode(refresh_payload, JWT_REFRESH_SECRET, algorithm="HS256")

    response = jsonify({"message": "Backup code verified"})
    response.set_cookie("access_token", access_token, httponly=True, secure=False, samesite="lax", max_age=15*60)
    response.set_cookie("refresh_token", refresh_token, httponly=True, secure=False, samesite="lax", max_age=60*60)

    return response

if __name__ == "__main__":
    app.run(debug=True)