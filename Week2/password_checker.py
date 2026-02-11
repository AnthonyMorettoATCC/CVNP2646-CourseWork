#!/usr/bin/env python3
# password_checker.py
# Evaluates password strength based on security requirements

def check_password_strength(password):
    """
    Evaluates password strength.
    Returns a tuple: (strength_level, list_of_requirements)

    Strength levels: "WEAK", "MEDIUM", "STRONG"
    """
    requirements_met = 0
    requirements = []

    # Requirement 1: Length (at least 8 characters)
    if len(password) >= 8:
        requirements_met += 1
        requirements.append("✓ At least 8 characters")
    else:
        requirements.append("✗ At least 8 characters")

    # Requirement 2: Lowercase letter
    if any(c.islower() for c in password):
        requirements_met += 1
        requirements.append("✓ Contains lowercase letters")
    else:
        requirements.append("✗ Contains lowercase letters")

    # Requirement 3: Uppercase letter
    if any(c.isupper() for c in password):
        requirements_met += 1
        requirements.append("✓ Contains uppercase letters")
    else:
        requirements.append("✗ Contains uppercase letters")

    # Requirement 4: Number
    if any(c.isdigit() for c in password):
        requirements_met += 1
        requirements.append("✓ Contains numbers")
    else:
        requirements.append("✗ Contains numbers")

    # Requirement 5: Special character
    special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    if any(c in special_chars for c in password):
        requirements_met += 1
        requirements.append("✓ Contains special characters")
    else:
        requirements.append("✗ Contains special characters")

    # Determine strength level
    if requirements_met == 5:
        strength = "STRONG"
    elif requirements_met >= 3:
        strength = "MEDIUM"
    else:
        strength = "WEAK"

    return strength, requirements


# Main program
print("=== Password Strength Checker ===\n")

# Test cases
test_passwords = [
    "password",           # Weak - no uppercase, numbers, special chars
    "Password1",          # Medium - missing special chars
    "P@ssw0rd!",          # Strong - meets all requirements
    "abc123",             # Weak - too short, no uppercase, no special
    "MySecureP@ss123"     # Strong - meets all requirements
]

print("Testing sample passwords:\n")
for pwd in test_passwords:
    strength, requirements = check_password_strength(pwd)
    print(f"Password: '{pwd}'")
    print(f"Strength: {strength}")
    print("Requirements:")
    for req in requirements:
        print(f"  {req}")
    print()

# Interactive mode
print("="*50)
user_password = input("\nEnter a password to check: ")
strength, requirements = check_password_strength(user_password)

print(f"\n{'='*50}")
print(f"Password Strength: {strength}")
print(f"{'='*50}")
print("\nRequirements:")
for req in requirements:
    print(f"  {req}")

if strength == "STRONG":
    print("\n✅ This is a STRONG password!")
elif strength == "MEDIUM":
    print("\n⚠️  This password is MEDIUM strength. Consider improving it.")
else:
    print("\n❌ This is a WEAK password. Please strengthen it.")