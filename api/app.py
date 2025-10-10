from flask import Flask, render_template, request, redirect, session
import hashlib
import os
from pymongo import MongoClient

app = Flask(__name__,static_folder="../static",template_folder="../templates")
app.secret_key = os.getenv("FLASK_SECRET_KEY", "your_secure_secret_key")

MONGODB_URI = os.getenv("MONGODB_URI")

if "tls=true" not in MONGODB_URI:
    if "?" in MONGODB_URI:
        MONGODB_URI += "&tls=true"
    else:
        MONGODB_URI += "?tls=true"


# MongoDB connection
client = MongoClient(MONGODB_URI)
db = client["registration"]
users = db["user"]
collection = db["menu_items"]

# Categories
CATEGORIES = ['cofee', 'tiffin', 'juices','milkshake', 'ice-cream','burger','pizza','sandwiches','nodiels','veg-meals','non-veg meals','veg-biryani','egg-biryani','hyderabadi-chicken-biryani','fish-biryani','mutton-biryani']


@app.route('/testdb')
def test_db():
    try:
        client.admin.command('ping')
        return "MongoDB connection successful!"
    except Exception as e:
        return f"MongoDB connection failed: {e}"

# Password Hashing
def generate_password_hash(password):
    return hashlib.sha256(password.encode()).hexdigest()

def check_password_hash(hashed_password, input_password):
    return hashed_password == generate_password_hash(input_password)

# Add item to DB
def add_item(category, name, price, image_url):
    collection.insert_one({
        "category": category.lower(),
        "name": name,
        "price": price,
        "image": image_url
    })

# Remove item from DB
def remove_item(category, name):
    return collection.delete_one({
        "category": category.lower(),
        "name": name.lower(),
    })

# Routes
@app.route('/')
def home():
    if 'email' in session:
        return redirect('/admin-dashboard') if session['role'] == 'admin' else redirect('/foodmenu')
    return redirect('/login')

import traceback

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            email = request.form.get('email')
            password = request.form.get('password')

            if not email or not password:
                return render_template('register.html', error="Email and Password are required.")

            hashed_password = generate_password_hash(password)

            if users.find_one({"email": email}):
                return render_template('register.html', error="Email already registered.")

            users.insert_one({"email": email, "password": hashed_password, "role": "user"})
            return redirect('/login')

        except Exception as e:
            print("Exception in register:", e)
            traceback.print_exc()
            return render_template('register.html', error="Internal server error occurred.")
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            email = request.form.get('email')
            password = request.form.get('password')

            if not email or not password:
                return render_template('login.html', error="Email and Password required.")

            user = users.find_one({"email": email})

            if user and check_password_hash(user['password'], password):
                session['email'] = user['email']
                session['role'] = user['role']
                return redirect('/admin-dashboard' if user['role'] == 'admin' else '/foodmenu')
            else:
                return render_template('login.html', error="Invalid email or password.")
        except Exception as e:
            print("Exception in login:", e)
            traceback.print_exc()  # Prints full traceback to console/logs
            return render_template('login.html', error="Internal server error occurred.")
    return render_template('login.html')


@app.route('/admin-dashboard')
def admin_dashboard():
    if 'email' not in session or session['role'] != 'admin':
        return redirect('/login')
    return render_template('admin_dashboard.html', categories=CATEGORIES, email=session['email'])

@app.route('/add_item', methods=['POST'])
def add_menu_item():
    if 'email' not in session or session['role'] != 'admin':
        return redirect('/login')
    add_item(
        request.form['category'],
        request.form['name'],
        float(request.form['price']),
        request.form['image_url']
    )
    return redirect('/admin-dashboard')

@app.route('/remove_item', methods=['POST'])
def remove_menu_item():
    if 'email' not in session or session['role'] != 'admin':
        return redirect('/login')
    remove_item(request.form['category'], request.form['name'])
    return redirect('/admin-dashboard')

@app.route('/foodmenu')
def foodmenu():
    if 'email' not in session or session['role'] != 'user':
        if 'email' not in session or session['role'] != 'admin':
            return redirect('/login')

    menu_by_category = {}
    for category in CATEGORIES:
        menu_by_category[category] = list(collection.find({"category": category}))
    
    return render_template('foodmenu.html', menu_by_category=menu_by_category, email=session['email'])

@app.route('/cart')
def cart():
    if 'email' not in session or session.get('role') != 'user':
        return redirect('/login')

    return render_template('cart.html', email=session['email'])

@app.route('/placeorder')
def placeorder():
    if 'email' not in session or session.get('role') != 'user':
        return redirect('/login')

    return render_template('placeorder.html', email=session['email'])

@app.route('/profile')
def profile():
    if 'email' not in session or session.get('role') != 'user':
        return redirect('/login')

    return render_template('profile.html', email=session['email'])

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True)
