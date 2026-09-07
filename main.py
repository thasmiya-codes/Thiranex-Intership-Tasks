import re
import secrets
import string
import sqlite3
import bcrypt

SYMBOLS = "@$!%*?&#^-_"

# Database Setup
conn = sqlite3.connect("users.db")
cursor = conn.cursor()
cursor.execute("""
    CREATE TABLE IF NOT EXISTS password_history (
        user_id INTEGER,
        password_hash TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
""")
conn.commit()

def analyze_password(password):
    length_criteria = len(password) >= 12
    upper_criteria = bool(re.search(r'[A-Z]', password))
    lower_criteria = bool(re.search(r'[a-z]', password))
    digit_criteria = bool(re.search(r'\d', password))
    symbol_criteria = any(char in SYMBOLS for char in password)

    unique_ratio = len(set(password)) / len(password) if password else 0
    uniqueness_criteria = unique_ratio >= 0.5

    score = sum([
        length_criteria, upper_criteria, lower_criteria,
        digit_criteria, symbol_criteria, uniqueness_criteria
    ])

    suggestions = []
    if not length_criteria:
        suggestions.append("Make the password at least 12 characters long.")
    if not upper_criteria:
        suggestions.append("Add uppercase letters (A-Z).")
    if not lower_criteria:
        suggestions.append("Add lowercase letters (a-z).")
    if not digit_criteria:
        suggestions.append("Add numbers (0-9).")
    if not symbol_criteria:
        suggestions.append(f"Add special characters ({SYMBOLS}).")
    if not uniqueness_criteria:
        suggestions.append("Avoid repeating the same characters too much.")

    if score >= 5 and length_criteria:
        strength = 'Strong'
    elif 3 <= score < 5:
        strength = 'Moderate'
    else:
        strength = 'Weak'

    alternative = None
    if strength != 'Strong':
        alternative = generate_strong_alternative()

    return {
        'strength': strength,
        'score': score,
        'suggestions': suggestions,
        'alternative': alternative
    }

def generate_strong_alternative(length=16):
    all_chars = string.ascii_letters + string.digits + SYMBOLS
    password = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice(SYMBOLS)
    ]
    password += [secrets.choice(all_chars) for _ in range(length - 4)]
    secrets.SystemRandom().shuffle(password)
    return ''.join(password)

def is_password_reused(user_id, new_password, history_limit=5):
    cursor.execute("""
        SELECT password_hash FROM password_history 
        WHERE user_id = ? 
        ORDER BY created_at DESC 
        LIMIT ?
    """, (user_id, history_limit))
    past_hashes = cursor.fetchall()
    
    for (stored_hash,) in past_hashes:
        if bcrypt.checkpw(new_password.encode('utf-8'), stored_hash.encode('utf-8')):
            return True
    return False

def save_password_hash(user_id, plain_password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(plain_password.encode('utf-8'), salt)
    cursor.execute(
        "INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)",
        (user_id, hashed.decode('utf-8'))
    )
    conn.commit()

# Main Execution
if __name__ == "__main__":
    user_id = 1
    user_password = input("Enter a password to test: ").strip()

    if is_password_reused(user_id, user_password):
        print("\n❌ Error: You cannot reuse a recent password.")
        print(f"💡 Suggested Strong Alternative: {generate_strong_alternative()}")
    else:
        result = analyze_password(user_password)
        print(f"\nStrength: {result['strength']} (Score: {result['score']}/6)")

        if result['suggestions']:
            print("\nSuggestions to improve:")
            for s in result['suggestions']:
                print(f"- {s}")

        if result['alternative']:
            print(f"\n💡 Suggested Strong Alternative: {result['alternative']}")
        else:
            save_password_hash(user_id, user_password)
            print("\n✅ Password is strong and saved successfully.")
