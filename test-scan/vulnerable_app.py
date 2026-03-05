"""
A sample application with some security issues for testing AgentSec.
"""

import subprocess
import os

# Hardcoded password - BAD!
api_key = "sk-1234567890abcdef"
password = "admin123"

def execute_user_command(user_input):
    """Execute user input - DANGEROUS!"""
    # Using eval() is very dangerous
    result = eval(user_input)
    return result

def run_shell_command(cmd):
    """Run a shell command"""
    # Using subprocess can be dangerous
    output = subprocess.check_output(cmd, shell=True)
    return output

def safe_function():
    """This function is safe"""
    return "Hello, World!"

if __name__ == "__main__":
    print(safe_function())
