import csv
import sqlite3
from werkzeug.security import generate_password_hash

# Paths
db_path = 'gov_ease.db'
csv_path = 'gov_ease.csv'

# Connect to SQLite database
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Drop and recreate the `bot_responses` table
cursor.execute("DROP TABLE IF EXISTS bot_responses")
cursor.execute("""
CREATE TABLE bot_responses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    query TEXT NOT NULL,
    response TEXT NOT NULL,
    persons TEXT,
    time TEXT
)
""")
print("Table `bot_responses` created successfully.")

# Drop and recreate the `users` table
cursor.execute("DROP TABLE IF EXISTS users")
cursor.execute("""
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
)
""")
print("Table `users` created successfully.")

# Read and insert data from the CSV file into `bot_responses`
try:
    with open(csv_path, 'r', encoding='utf-8') as csv_file:
        reader = csv.DictReader(csv_file)
        for row in reader:
            query = row.get('query', '').strip()
            response = row.get('response', '').strip()
            persons = row.get('persons', '').strip()
            time = row.get('time', '').strip()

            # Skip rows with missing required fields
            if not query or not response:
                print(f"Skipping row due to missing data: {row}")
                continue

            # Insert into the database
            cursor.execute("""
            INSERT INTO bot_responses (query, response, persons, time)
            VALUES (?, ?, ?, ?)
            """, (query, response, persons, time))
    print("Data successfully inserted into the `bot_responses` table.")
except FileNotFoundError:
    print(f"CSV file not found at path: {csv_path}")

# Commit changes and close the database connection
conn.commit()
conn.close()

print("Database setup completed successfully!")
