from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from rapidfuzz import fuzz  # Import RapidFuzz for fuzzy matching

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Required for session management and flash messages

# Helper function to query the database
def query_response(user_query):
    try:
        conn = sqlite3.connect('gov_ease.db')
        cursor = conn.cursor()

        cursor.execute("SELECT DISTINCT query FROM bot_responses")
        all_queries = cursor.fetchall()

        best_match = None
        highest_score = 0
        for query in all_queries:
            query_text = query[0]
            score = fuzz.partial_ratio(user_query, query_text)
            if score > highest_score:
                highest_score = score
                best_match = query_text

        if highest_score > 70:  # Adjust this threshold as needed
            cursor.execute("""SELECT response, persons, time 
                              FROM bot_responses WHERE query = ?""", (best_match,))
            results = cursor.fetchall()
            conn.close()
            return best_match, results

        conn.close()
        return None, []
    except Exception as e:
        print(f"Error querying the database: {e}")
        return None, []

# Helper function to get DB connection
def get_db_connection():
    conn = sqlite3.connect('gov_ease.db')
    conn.row_factory = sqlite3.Row  # This allows you to access columns by name
    return conn

# Route for chatbot UI
@app.route('/')
def index():
    user_name = session.get('user_name')  # Get the user's name from the session
    return render_template('index.html', user_name=user_name)

# Route for the login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['user_name'] = user['name']  # Store the user's name in the session
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password. Please try again.', 'danger')

        conn.close()

    return render_template('login.html')

# Route for the logout page
@app.route('/logout')
def logout():
    session.clear()  # Clear all session data
    flash('You have successfully logged out.', 'success')
    return redirect(url_for('login'))

# Route for the sign-up page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match. Please try again.', 'danger')
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""INSERT INTO users (name, email, password) VALUES (?, ?, ?)""",
                           (name, email, hashed_password))
            conn.commit()
            flash('Account created successfully! You can now log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Email already exists. Please log in.', 'danger')
        finally:
            conn.close()

    return render_template('signup.html')

# Route for chatbot API
@app.route('/chat', methods=['POST'])
def chat():
    user_message = request.json.get('message', '').strip().lower()
    print(f"Received message: {user_message}")

    matched_query, responses = query_response(user_message)

    if responses:
        if matched_query.lower().startswith("how to get"):
            prefix = "To get the"
        elif matched_query.lower().startswith("how to use"):
            prefix = "To use the"
        else:
            prefix = "For"

        reply = f"<b>{matched_query.split('?')[0]}:</b><br><br>"
        for index, row in enumerate(responses):
            step = f"{row[0]}<br>Accountable Person: {row[1]}<br>Time: {row[2]}<br><br>"
            reply += step

        reply += "<b>END OF TRANSACTION</b>"
    else:
        reply = "Sorry, I didn't understand that. Please ask about Barangay Local Government Unit services."

    return jsonify({'reply': reply})

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)
