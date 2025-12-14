import sqlite3
import bcrypt

DATABASE_NAME = 'database.db'

def create_user(username, password):
    # Hash the password
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    
    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()
    
    try:
        # Insert the new user into the database
        cursor.execute('''
            INSERT INTO users (username, password)
            VALUES (?, ?)
        ''', (username, hashed_password))

        connection.commit()
        print(f"User '{username}' created successfully.")
    except sqlite3.IntegrityError:
        print(f"Error: Username '{username}' already exists.")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        connection.close()

if __name__ == "__main__":
    # Prompt for user input
    username = input("Enter the username: ")
    password = input("Enter the password: ")
    create_user(username, password)
