#!/usr/bin/env python3
# hex_converter.py
# Converts between hexadecimal and decimal values

def hex_to_decimal(hex_value):
    """
    Converts hexadecimal string to decimal integer.

    Parameters:
    - hex_value: String representation of hex (e.g., "FF", "2A", "100")

    Returns: Decimal integer
    """
    # Remove '0x' prefix if present
    if hex_value.startswith('0x') or hex_value.startswith('0X'):
        hex_value = hex_value[2:]

    # Convert using base 16
    decimal_value = int(hex_value, 16)
    return decimal_value


def decimal_to_hex(decimal_value):
    """
    Converts decimal integer to hexadecimal string.

    Parameters:
    - decimal_value: Integer to convert

    Returns: Hexadecimal string with '0x' prefix
    """
    hex_value = hex(decimal_value)
    return hex_value


# Main program
print("=" * 70)
print("HEXADECIMAL ⟷ DECIMAL CONVERTER")
print("=" * 70)
print("Common use cases: Memory addresses, color codes, network protocols\n")

# Test Case 1: Common hex values
print("--- Test Case 1: Common Hexadecimal Values ---")
print("-" * 70)

test_hex_values = [
    ("FF", "Maximum value in one byte"),
    ("2A", "Answer to everything (42 in decimal)"),
    ("100", "256 in decimal - one byte overflow")
]

for hex_val, description in test_hex_values:
    decimal = hex_to_decimal(hex_val)
    print(f"Hex: 0x{hex_val:>4}  →  Decimal: {decimal:>5}  ({description})")

# Test Case 2: Memory address example
print("\n--- Test Case 2: Memory Address Analysis ---")
print("-" * 70)

memory_addresses = ["7FFE", "BEEF", "DEAD", "C0DE"]
print("Converting memory addresses to decimal:")

for addr in memory_addresses:
    decimal = hex_to_decimal(addr)
    binary = bin(decimal)[2:].zfill(16)  # Show binary too
    print(f"0x{addr}  =  {decimal:>5} decimal  =  {binary} binary")

# Test Case 3: Reverse conversion (decimal to hex)
print("\n--- Test Case 3: Decimal to Hexadecimal Conversion ---")
print("-" * 70)

decimal_values = [255, 1024, 65535, 16777215]
print("Converting decimal values to hexadecimal:")

for dec_val in decimal_values:
    hex_val = decimal_to_hex(dec_val)
    print(f"Decimal: {dec_val:>10}  →  Hex: {hex_val}")

# Interactive mode
print("\n" + "=" * 70)
print("INTERACTIVE MODE")
print("=" * 70)

print("\nChoose conversion direction:")
print("1. Hexadecimal → Decimal")
print("2. Decimal → Hexadecimal")

choice = input("\nEnter choice (1 or 2): ")

if choice == "1":
    hex_input = input("Enter hexadecimal value (e.g., FF, 0x2A, BEEF): ")
    try:
        result = hex_to_decimal(hex_input)
        print(f"\n{'=' * 70}")
        print(f"Hexadecimal: 0x{hex_input.upper().replace('0X', '')}")
        print(f"Decimal:     {result}")
        print(f"Binary:      {bin(result)}")
        print(f"{'=' * 70}")

        # Real-world context
        print(f"\n💡 Real-World Application:")
        if result <= 255:
            print(f"   This fits in 1 byte (8 bits)")
            print(f"   Could represent: RGB color component, single byte of data")
        elif result <= 65535:
            print(f"   This fits in 2 bytes (16 bits)")
            print(f"   Could represent: Network port, memory offset, Unicode character")
        else:
            print(f"   This requires {(result.bit_length() + 7) // 8} bytes")
            print(f"   Could represent: Memory address, large integer value")

    except ValueError:
        print("\n❌ Error: Invalid hexadecimal value")

elif choice == "2":
    decimal_input = int(input("Enter decimal value: "))
    result = decimal_to_hex(decimal_input)
    print(f"\n{'=' * 70}")
    print(f"Decimal:     {decimal_input}")
    print(f"Hexadecimal: {result}")
    print(f"Binary:      {bin(decimal_input)}")
    print(f"{'=' * 70}")

else:
    print("\n❌ Invalid choice")