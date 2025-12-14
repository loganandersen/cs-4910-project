import subprocess
import sys
import time
import os

def run_script(script_name, interactive=False):
    print(f"\n--- Running {script_name} ---\n")
    
    if interactive:
        # Let the script handle input/output directly
        result = subprocess.run([sys.executable, script_name])
        if result.returncode != 0:
            raise SystemExit(f"Error running {script_name}, exiting.")
    else:
        # Non-interactive scripts can capture output
        result = subprocess.run([sys.executable, script_name], capture_output=True, text=True)
        print(result.stdout)
        if result.returncode != 0:
            print(result.stderr)
            raise SystemExit(f"Error running {script_name}, exiting.")
            


while True:
    action = input(
        "\nLog in   1:\n"
        "New user 2:\n"
        "To exit  3:\n"
    )

    match action:
        case "1":
            # Ensure the 'users' folder exists
            base_dir = "users"
            if not os.path.exists(base_dir):
                os.makedirs(base_dir)

            # Get list of existing usernames (folders)
            existing_users = [name for name in os.listdir(base_dir) if os.path.isdir(os.path.join(base_dir, name))]

            # Ask for username
            username = input("Enter username: ").strip()

            if username in existing_users:
                
                with open("active_user.txt", "w") as f:
                    f.write(f"{username}\n")
             
                loop = "enter"
                while loop != "leave":
                    action = input("\nWhat would you like to do: \n"
                                   "1: Fetch old 2FA: \n"
                                   "2: Make new 2FA: \n"
                                   "3: Access data: \n"
                                   "4: Go back: \n"
                                )
                    match action:
                        case "1":
                            # Send email with QR code
                            run_script("email_test.py")
                        case "2":
                            # Generate secret and QR code
                            run_script("generate_secret.py")
                            
                            # Send email with QR code
                            run_script("email_test.py")
                            
                            # Verify secret with user input (interactive)
                            run_script("verify_secret.py", interactive=True)
                            
                        case "3":
                            # Verify secret with user input (interactive)
                            run_script("verify_secret.py", interactive=True)
                            
                        case "4":
                            os.remove("active_user.txt")
                            loop = "leave"
                        case _:
                            print("Invalid option, to go back press 3:")

            else:
                print("User does not exist, select option 2 for a new user.")           

        case "2":
            # Generate a new user
            run_script("new_user_data.py", interactive=True)

        case "3":
            # Exit program
            print("Exiting...")
            time.sleep(3)
            break   # exits the while loop

        case _:
            print("Invalid choice. Please try again.")



print("\nAll scripts executed successfully!")
