from flask import Flask, render_template, request, jsonify, send_from_directory,session,redirect, url_for
import cv2
import numpy as np
import base64
import mediapipe as mp
import joblib
import stanza
import os

import os
import string
import random
from flask import Flask, request, jsonify
from flask_mail import Mail, Message
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from flask_cors import CORS


load_dotenv()

app = Flask(__name__, static_folder='static', static_url_path='')
app.secret_key = os.getenv("SECRET_KEY", "super-secret-key")
CORS(app)

# ==============================
# MongoDB
# ==============================
client = MongoClient(os.getenv("MONGO_URI"))
db = client["SignBridge"]
users_collection = db["users"]

# ==============================
# Flask-Mail
# ==============================
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.getenv("EMAIL_USER")
app.config["MAIL_PASSWORD"] = os.getenv("EMAIL_PASS")

mail = Mail(app)

# ==============================
# OTP Store (memory)
# ==============================
otp_store = {}

# ==============================
# Helpers
# ==============================
def generate_otp():
    return "".join(random.choices(string.digits, k=6))


def is_strong_password(password):
    return (
        len(password) >= 8 and
        any(c.isupper() for c in password) and
        any(c.islower() for c in password) and
        any(c.isdigit() for c in password)
    )


def otp_is_valid(email, otp):
    return otp_store.get(email) == otp


# ==============================
# Register
# ==============================
# temporary store
pending_users = {}

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    email = data.get("email")
    password = data.get("password")

    if users_collection.find_one({"email": email}):
        return jsonify({"error": "Email already exists"}), 400

    if not is_strong_password(password):
        return jsonify({"error": "Weak password"}), 400

    otp = generate_otp()

    # store temporarily (NOT DB)
    pending_users[email] = {
        "password": generate_password_hash(password),
        "otp": otp
    }

    msg = Message(
        "Your OTP",
        sender=app.config["MAIL_USERNAME"],
        recipients=[email]
    )
    msg.body = f"OTP: {otp}"
    mail.send(msg)

    return jsonify({"message": "OTP sent"}), 200



# ==============================
# Verify Registration OTP
# ==============================
@app.route("/verify-registration-otp", methods=["POST"])
def verify_registration_otp():
    data = request.json
    email = data.get("email")
    otp = data.get("otp")

    user = pending_users.get(email)

    if not user or user["otp"] != otp:
        return jsonify({"error": "Invalid OTP"}), 400

    
    users_collection.insert_one({
        "email": email,
        "password": user["password"]
    })

    del pending_users[email]

    return jsonify({"message": "Registration successful"}), 200



# ==============================
# Login
# ==============================
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    email = data.get("email")
    password = data.get("password")

    user = users_collection.find_one({"email": email})

    if not user or not check_password_hash(user["password"], password):
        return jsonify({"error": "Invalid credentials"}), 400

    otp = generate_otp()
    otp_store[email] = otp

    msg = Message(
        "Your OTP for Login",
        sender=app.config["MAIL_USERNAME"],
        recipients=[email]
    )
    msg.body = f"Your OTP is: {otp}. It will expire in 10 minutes."
    mail.send(msg)

    return jsonify({"message": "Credentials verified. OTP sent"}), 200


# ==============================
# Verify Login OTP
# ==============================
@app.route("/verify-login-otp", methods=["POST"])
def verify_login_otp():
    data = request.json
    email = data.get("email")
    otp = data.get("otp")

    if otp_is_valid(email, otp):
        del otp_store[email]
        session["user"] = email
        session.permanent = True
        return jsonify({"message": "Login successful"}), 200

    return jsonify({"error": "Invalid OTP"}), 400


# ==============================
# Forgot Password - Send OTP
# ==============================
@app.route("/send-otp-for-password", methods=["POST"])
def send_otp_for_password():
    data = request.json
    email = data.get("email")

    if not users_collection.find_one({"email": email}):
        return jsonify({"error": "Email not found"}), 404

    otp = generate_otp()
    otp_store[email] = otp

    msg = Message(
        "Your OTP for Password Reset",
        sender=app.config["MAIL_USERNAME"],
        recipients=[email]
    )
    msg.body = f"Your OTP is: {otp}. It will expire in 10 minutes."
    mail.send(msg)

    return jsonify({"message": "OTP sent successfully"}), 200


# ==============================
# Verify Password OTP
# ==============================
@app.route("/verify-otp-for-password", methods=["POST"])
def verify_otp_for_password():
    data = request.json
    email = data.get("email")
    otp = data.get("otp")

    if otp_is_valid(email, otp):
        return jsonify({"message": "OTP verified successfully"}), 200

    return jsonify({"error": "Invalid OTP"}), 400


# ==============================
# Update Password
# ==============================
@app.route("/update-password", methods=["POST"])
def update_password():
    data = request.json
    email = data.get("email")
    new_password = data.get("newPassword")
    confirm_password = data.get("confirmNewPassword")
    otp = data.get("otp")

    if not otp_is_valid(email, otp):
        return jsonify({"error": "Invalid OTP"}), 400

    if new_password != confirm_password:
        return jsonify({"error": "Passwords do not match"}), 400

    if not is_strong_password(new_password):
        return jsonify({
            "error": "Password must be 8+ chars with uppercase, lowercase, number"
        }), 400

    hashed_password = generate_password_hash(new_password)

    users_collection.update_one(
        {"email": email},
        {"$set": {"password": hashed_password}}
    )

    del otp_store[email]

    return jsonify({"message": "Password reset successfully"}), 200



# =====================================================
# LOAD SIGN → TEXT MODEL (camera prediction)
# =====================================================
model = joblib.load("modell.joblib")

labels_dict = {
0:'1',1:'2',2:'3',3:'4',4:'5',5:'6',6:'7',7:'8',8:'9',
9:'A',10:'B',11:'C',12:'D',13:'E',14:'F',15:'G',16:'H',
17:'I',18:'J',19:'K',20:'L',21:'M',22:'N',23:'O',24:'P',
25:'Q',26:'R',27:'S',28:'T',29:'U',30:'V',31:'W',32:'X',
33:'Y',34:'Z',35:'Hello',36:'Indian',37:'Namasthe',38:'Man',
39:'Woman',40:'Again',41:'Me',42:'You',43:'Deaf',44:'Blind',
45:'Happy',46:'Thankyou',47:'Beautiful',48:'Difficult',
49:'Food',50:'Nice',51:'House',52:'Flower',53:'Fool',
54:'What',55:'When',56:'Good',57:'Sleep',58:'Badsmell',59:'Headache'
}

mp_hands = mp.solutions.hands

hands = mp_hands.Hands(
    static_image_mode=True,
    max_num_hands=2,
    model_complexity=1,
    min_detection_confidence=0.3,
    min_tracking_confidence=0.3
)

# =====================================================
# LOAD TEXT → SIGN NLP (stanza)
# =====================================================
stanza.download('en', verbose=False)
nlp = stanza.Pipeline('en', processors='tokenize,pos,lemma', use_gpu=False)

STOP_WORDS = {
    "am","is","are","was","were","be","been","being",
    "have","has","had","do","does","did",
    "will","shall","can","could","should","would",
    "may","might","must","to","the","an"
}

VALID_WORDS = set(open("words.txt").read().splitlines())


def text_to_isl(text):
    doc = nlp(text)
    result = []

    for sent in doc.sentences:
        for word in sent.words:

            lemma = word.lemma.lower()

            if word.upos == "PUNCT":
                continue
            if lemma in STOP_WORDS:
                continue

            if lemma in VALID_WORDS:
                result.append(lemma)
            else:
                result.extend(list(lemma))

    return result


# =====================================================
# ROUTES (PAGES)
# =====================================================

# Home → sign to text (camera)
@app.route('/')
def index():
    return render_template("index.html")

@app.route('/signin')
def signin():
    return render_template('signin.html')  

@app.route('/register')
def register_page():
    return render_template('signup.html')  

@app.route('/home')
def home():
    if "user" not in session:
        return render_template("signin.html")
    return render_template("home.html")
@app.route('/signout')
def signout():
    session.clear()
    return redirect(url_for('index')) 

@app.route('/reset')
def reset():
    return render_template('forgot_password.html') 





# sign → text page
@app.route('/signtext')
def signtext():
    return render_template("sign_to_text.html")

# Text → sign avatar page
@app.route('/textsign')
def textsign():
    return render_template("text_to_sign.html")


# =====================================================
# API 1 — SIGN → TEXT
# =====================================================

@app.route('/stpredict', methods=['POST'])
def stpredict():

    data = request.json['image']

    img_bytes = base64.b64decode(data.split(',')[1])
    np_img = np.frombuffer(img_bytes, np.uint8)
    frame = cv2.imdecode(np_img, cv2.IMREAD_COLOR)

    frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
    results = hands.process(frame_rgb)

    prediction_text = ""
    landmarks_out = []

    if results.multi_hand_landmarks:
        for hand_landmarks in results.multi_hand_landmarks:

            single_hand = []
            landmarks = hand_landmarks.landmark

            for lm in landmarks:
                single_hand.append([lm.x, lm.y])

            landmarks_out.append(single_hand)


            x_coords = [lm.x for lm in landmarks]
            y_coords = [lm.y for lm in landmarks]

            min_x, max_x = min(x_coords), max(x_coords)
            min_y, max_y = min(y_coords), max(y_coords)

            width = max_x - min_x
            height = max_y - min_y

            data_aux = []

            for lm in landmarks:
                norm_x = (lm.x - min_x) / width if width else 0
                norm_y = (lm.y - min_y) / height if height else 0
                data_aux.extend([norm_x, norm_y])

            if len(data_aux) == 42:
                pred = model.predict([data_aux])[0]
                prediction_text = labels_dict[int(pred)]

    return jsonify({
        "prediction": prediction_text,
        "landmarks": landmarks_out
    })


# =====================================================
# API 2 — TEXT → SIGN
# =====================================================
@app.route('/tspredict', methods=['POST'])
def tspredict():

    text = request.form.get('text', '')

    words = text_to_isl(text)

    # return list (ordered)
    return jsonify(words)


# serve static (for sigml, css, js)
@app.route('/static/<path:path>')
def serve_static(path):
    return send_from_directory('static', path)


# =====================================================
if __name__ == '__main__':
    app.run(debug=False)
