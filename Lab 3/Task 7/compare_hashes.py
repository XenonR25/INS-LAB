#!/usr/bin/env python3

def hex_to_binary(hex_str):
    """Convert a hex string to a binary string."""
    # Remove the '(stdin)= ' part if present from openssl output
    if '=' in hex_str:
        clean_hex = hex_str.split('=')[1].strip()
    else:
        clean_hex = hex_str.strip()


    # Convert to binary and pad to 256 bits for SHA256
    return bin(int(clean_hex, 16))[2:].zfill(256)

def count_same_bits(str1, str2):
    """Count how many bits are the same between two binary strings."""
    return sum(1 for bit1, bit2 in zip(str1, str2) if bit1 == bit2)

# Replace these with your actual H1 and H2 values from openssl
H1_hex = "c03905fcdab297513a620ec81ed46ca44ddb62d41cbbd83eb4a5a3592be26a69"
H2_hex = "93e1bdbe1b25b7cb9e0a61ca8095b4c730021da11361406a71fd074aba0ee8e9"

# Convert to binary
H1_bin = hex_to_binary(H1_hex)
H2_bin = hex_to_binary(H2_hex)

# Count matching bits
same_bits = count_same_bits(H1_bin, H2_bin)
total_bits = len(H1_bin)
different_bits = total_bits - same_bits

print("=== HASH COMPARISON RESULTS ===")
print(f"Total bits compared: {total_bits}")
print(f"Same bits: {same_bits}")
print(f"Different bits: {different_bits}")
print(f"Percentage similarity: {(same_bits/total_bits)*100:.2f}%")

# Show a small sample of the binary comparison
print("\n=== SAMPLE OF FIRST 50 BITS ===")
print(f"H1: {H1_bin[:50]}")
print(f"H2: {H2_bin[:50]}")
