from flask import Flask, render_template, request, redirect, session
import hashlib
import os
from pymongo import MongoClient

app = Flask(__name__)
app.secret_key = "your_secure_secret_key"

# MongoDB connection
client = MongoClient(os.environ["MONGODB_URI"])
db = client[os.environ.get("DATABASE_NAME", "registration")]
users = db["user"]
collection = db["menu_items"]


client = None
db = None
users = None
collection = None

def get_db():
    global client, db, users, collection
    if not client:
        client = MongoClient(os.environ["MONGODB_URI"], serverSelectionTimeoutMS=5000)
        client.server_info()  # Force connection check
        db = client[os.environ.get("DATABASE_NAME", "registration")]
        users = db["user"]
        collection = db["menu_items"]
    return db, users, collection

# Categories
CATEGORIES = ['cofee', 'tiffin', 'juices','milkshake', 'ice-cream','burger','pizza','sandwiches','nodiels','veg-meals','non-veg meals','veg-biryani','egg-biryani','hyderabadi-chicken-biryani','fish-biryani','mutton-biryani']

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
    db, users, collection = get_db()
    if 'email' in session:
        return redirect('/admin-dashboard') if session['role'] == 'admin' else redirect('/foodmenu')
    return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    db, users, collection = get_db()
    if request.method == 'POST':
        email = request.form['email']
        password = generate_password_hash(request.form['password'])

        if users.find_one({"email": email}):
            return render_template('register.html', error="Email already registered.")
        
        users.insert_one({"email": email, "password": password, "role": "user"})
        return redirect('/login')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    db, users, collection = get_db()
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = users.find_one({"email": email})

        if user and check_password_hash(user['password'], password):
            session['email'] = user['email']
            session['role'] = user['role']
            return redirect('/admin-dashboard' if user['role'] == 'admin' else '/foodmenu')
        return render_template('login.html', error="Invalid email or password.")
    return render_template('login.html')

@app.route('/admin-dashboard')
def admin_dashboard():
    db, users, collection = get_db()
    if 'email' not in session or session['role'] != 'admin':
        return redirect('/login')
    return render_template('admin_dashboard.html', categories=CATEGORIES, email=session['email'])

@app.route('/add_item', methods=['POST'])
def add_menu_item()
    db, users, collection = get_db()

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
    db, users, collection = get_db()
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

handler = app
