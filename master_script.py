import subprocess
import sys

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

# 1. Generate secret and QR code
run_script("generate_secret.py")

# 2. Send email with QR code
run_script("emailtest.py")

# 3. Verify secret with user input (interactive)
run_script("verify_secret.py", interactive=True)

print("\nAll scripts executed successfully!")
