"""
run_tests.py — installs dependencies and runs the test suite.
Usage: python run_tests.py
"""
import subprocess
import sys
import os

PYTHON = sys.executable
BASE = os.path.dirname(__file__)
LOG = os.path.join(BASE, "test_output.txt")

def run(cmd, label):
    print(f"\n>>> {label}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    out = result.stdout + result.stderr
    print(out)
    return result.returncode, out

lines = []

# 1. Install requirements
code, out = run([PYTHON, "-m", "pip", "install", "-r", "requirements.txt", "--quiet"], "Installing requirements")
lines.append(f"=== pip install ===\n{out}\n")

# 2. Install pytest
code, out = run([PYTHON, "-m", "pip", "install", "pytest", "--quiet"], "Installing pytest")
lines.append(f"=== pip install pytest ===\n{out}\n")

# 3. Run tests
code, out = run([PYTHON, "-m", "pytest", "test_dirhawk.py", "-v", "--tb=short", "--no-header"], "Running tests")
lines.append(f"=== TEST RESULTS ===\n{out}\n")

# 4. Write log
with open(LOG, "w", encoding="utf-8") as f:
    f.write("\n".join(lines))

print(f"\nResults saved to: {LOG}")
print("Exit code:", code)
sys.exit(code)
