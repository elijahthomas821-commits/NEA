from flask import Flask, request, render_template, redirect, url_for, session
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash

from api import get_current_matchday

app = Flask(__name__)
app.secret_key = "Arsenal_are_the_best"

my_db = mysql.connector.connect(
    user="cs_S2403334",
    password="12345678",
    host="ND-COMPSCI",
    port="3306",
    database="cs_S2403334_Arsenal_are_the_best"
)


@app.route("/")
def home():
    return render_template("homepage.html")


def email_exists(email: str) -> bool:
    cursor = my_db.cursor()
    cursor.execute("SELECT 1 FROM users WHERE email = %s LIMIT 1", (email,))
    result = cursor.fetchone()
    cursor.close()
    return result is not None


def username_exists(username: str) -> bool:
    cursor = my_db.cursor()
    cursor.execute("SELECT 1 FROM users WHERE username = %s LIMIT 1", (username,))
    result = cursor.fetchone()
    cursor.close()
    return result is not None


def validate_password(password: str) -> bool:
    lowercase = "qwertyuiopasdfghjklzxcvbnm"
    uppercase = "QWERTYUIOPASDFGHJKLZXCVBNM"
    digits = "1234567890"
    special_chars = '!"£$%^&*()-=+_;:@~,./?><'

    has_lower = any(c in lowercase for c in password)
    has_upper = any(c in uppercase for c in password)
    has_digit = any(c in digits for c in password)
    has_special = any(c in special_chars for c in password)

    return has_lower and has_upper and has_digit and has_special


@app.route("/register", methods=["GET", "POST"])
def create_user():
    if request.method == "GET":
        return render_template("register.html")

    username = (request.form.get("username") or "").strip()
    first_name = (request.form.get("first_name") or "").strip()
    last_name = (request.form.get("last_name") or "").strip()
    email = (request.form.get("email") or "").strip()
    phone_number = (request.form.get("phone_number") or "").strip()
    address_line_1 = (request.form.get("address_line_1") or "").strip()
    city = (request.form.get("city") or "").strip()
    postcode = (request.form.get("postcode") or "").strip()
    password = request.form.get("password") or ""

    if not username or not first_name or not last_name or not email or not password:
        return "Missing required fields", 400

    if "@" not in email:
        return "Invalid email", 400

    if phone_number and "+" not in phone_number:
        return "Phone number must include country code, example +44...", 400

    if username_exists(username):
        return "This username is already in use", 409

    if email_exists(email):
        return "This email is already in use", 409

    if not validate_password(password):
        return "Password must include lower, upper, digit, special character", 400

    password_hash = generate_password_hash(
        password,
        method="pbkdf2:sha256",
        salt_length=16
    )

    user_id = f"{last_name}{first_name[0]}01"

    cursor = my_db.cursor()

    cursor.execute(
        "SELECT 1 FROM users WHERE user_id = %s LIMIT 1",
        (user_id,)
    )
    while cursor.fetchone() is not None:
        n = int(user_id[-2:]) + 1
        user_id = user_id[:-2] + f"{n:02d}"
        cursor.execute(
            "SELECT 1 FROM users WHERE user_id = %s LIMIT 1",
            (user_id,)
        )

    query = """
        INSERT INTO users
        (user_id, username, first_name, last_name, email, phone_number, address_line_1, city, postcode, password_hash)
        VALUES
        (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    values = (
        user_id, username, first_name, last_name, email,
        phone_number, address_line_1, city, postcode, password_hash
    )

    try:
        cursor.execute(query, values)
        my_db.commit()
    except mysql.connector.Error as err:
        my_db.rollback()
        cursor.close()
        return f"Database error: {err}", 500

    cursor.close()
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    email = (request.form.get("email") or "").strip()
    password = request.form.get("password") or ""

    cursor = my_db.cursor(dictionary=True)
    cursor.execute(
        "SELECT user_id, username, password_hash FROM users WHERE email = %s",
        (email,)
    )
    user = cursor.fetchone()
    cursor.close()

    if not user or not check_password_hash(user["password_hash"], password):
        return "Invalid login", 401

    session["user_id"] = user["user_id"]
    session["username"] = user["username"]
    return redirect(url_for("dashboard"))


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    matchday = get_current_matchday()
    matches = get_pl_matches(matchday)
    table = get_pl_table()

    return render_template(
        "dashboard.html",
        username=session.get("username"),
        matchday=matchday,
        matches=matches,
        table=table
    )


@app.route("/predict")
def predict_page():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("predict.html")

print(app.url_map)


if __name__ == "__main__":
    app.run(debug=True)

