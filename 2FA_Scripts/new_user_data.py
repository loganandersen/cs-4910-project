import os

while True:
    username = input("Enter username: ").strip()
    gmail = input("Enter Gmail address: ").strip().lower()

    if not username:
        print("Username cannot be empty.\n")
        continue

    if not gmail.endswith("@gmail.com"):
        print("Invalid Gmail address. Must be a Gmail account.\n")
        continue

    break

# Ensure base 'users' directory exists
base_dir = "users"
if not os.path.exists(base_dir):
    os.makedirs(base_dir)

# Create user folder (e.g., users/alice/)
user_dir = os.path.join(base_dir, username)
if not os.path.exists(user_dir):
    os.makedirs(user_dir)

# File path: users/alice/alice_data.txt
filename = os.path.join(user_dir, f"{username}_data.txt")

# Save user data
with open(filename, "w") as f:
    f.write(f"{username}\n")
    f.write(f"{gmail}\n")

print(f"User data saved.")

