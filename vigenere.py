#!/usr/bin/env python3
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# ==================== ORIGINAL VIGENÈRE CIPHER (UNCHANGED) ====================
def vigenere_encrypt(plaintext, key):
    encrypted = []
    key_length = len(key)
    if key_length == 0:
        print(Fore.RED + "[!] Error: Key cannot be empty.")
        return None
    for i, char in enumerate(plaintext):
        if char.isupper():
            shift = ord(key[i % key_length].upper()) - ord('A')
            encrypted_char = chr(((ord(char) - ord('A') + shift) % 26) + ord('A'))
            encrypted.append(encrypted_char)
        elif char.islower():
            shift = ord(key[i % key_length].lower()) - ord('a')
            encrypted_char = chr(((ord(char) - ord('a') + shift) % 26) + ord('a'))
            encrypted.append(encrypted_char)
        else:
            encrypted.append(char)
    return ''.join(encrypted)

def vigenere_decrypt(ciphertext, key):
    decrypted = []
    key_length = len(key)
    if key_length == 0:
        print(Fore.RED + "[!] Error: Key cannot be empty.")
        return None
    for i, char in enumerate(ciphertext):
        if char.isupper():
            shift = ord(key[i % key_length].upper()) - ord('A')
            decrypted_char = chr(((ord(char) - ord('A') - shift) % 26) + ord('A'))
            decrypted.append(decrypted_char)
        elif char.islower():
            shift = ord(key[i % key_length].lower()) - ord('a')
            decrypted_char = chr(((ord(char) - ord('a') - shift) % 26) + ord('a'))
            decrypted.append(decrypted_char)
        else:
            decrypted.append(char)
    return ''.join(decrypted)

# ==================== NEW: ROT13 CIPHER ====================
def rot13_cipher(text):
    """ROT13 - Same function for encrypt and decrypt"""
    result = []
    for char in text:
        if char.isupper():
            result.append(chr(((ord(char) - ord('A') + 13) % 26) + ord('A')))
        elif char.islower():
            result.append(chr(((ord(char) - ord('a') + 13) % 26) + ord('a')))
        else:
            result.append(char)
    return ''.join(result)

# ==================== NEW: CAESAR CIPHER ====================
def caesar_encrypt(plaintext, shift):
    """Caesar cipher encryption with custom shift"""
    try:
        shift = int(shift) % 26
    except ValueError:
        print(Fore.RED + "[!] Error: Shift must be a number.")
        return None
    
    encrypted = []
    for char in plaintext:
        if char.isupper():
            encrypted.append(chr(((ord(char) - ord('A') + shift) % 26) + ord('A')))
        elif char.islower():
            encrypted.append(chr(((ord(char) - ord('a') + shift) % 26) + ord('a')))
        else:
            encrypted.append(char)
    return ''.join(encrypted)

def caesar_decrypt(ciphertext, shift):
    """Caesar cipher decryption with custom shift"""
    try:
        shift = int(shift) % 26
    except ValueError:
        print(Fore.RED + "[!] Error: Shift must be a number.")
        return None
    
    decrypted = []
    for char in ciphertext:
        if char.isupper():
            decrypted.append(chr(((ord(char) - ord('A') - shift) % 26) + ord('A')))
        elif char.islower():
            decrypted.append(chr(((ord(char) - ord('a') - shift) % 26) + ord('a')))
        else:
            decrypted.append(char)
    return ''.join(decrypted)

# ==================== NEW: ATBASH CIPHER ====================
def atbash_cipher(text):
    """Atbash cipher - reverses the alphabet (A↔Z, B↔Y, etc.)"""
    result = []
    for char in text:
        if char.isupper():
            result.append(chr(ord('Z') - (ord(char) - ord('A'))))
        elif char.islower():
            result.append(chr(ord('z') - (ord(char) - ord('a'))))
        else:
            result.append(char)
    return ''.join(result)

# ==================== NEW: SUBSTITUTION CIPHER ====================
def substitution_encrypt(plaintext, key):
    """Substitution cipher - replaces each letter with another"""
    if len(key) != 26:
        print(Fore.RED + "[!] Error: Key must be exactly 26 characters.")
        return None
    
    alphabet = 'abcdefghijklmnopqrstuvwxyz'
    key_lower = key.lower()
    
    if len(set(key_lower)) != 26 or not all(c in alphabet for c in key_lower):
        print(Fore.RED + "[!] Error: Key must contain each letter exactly once.")
        return None
    
    encrypted = []
    for char in plaintext:
        if char.isupper():
            index = ord(char) - ord('A')
            encrypted.append(key[index].upper())
        elif char.islower():
            index = ord(char) - ord('a')
            encrypted.append(key_lower[index])
        else:
            encrypted.append(char)
    return ''.join(encrypted)

def substitution_decrypt(ciphertext, key):
    """Substitution cipher decryption"""
    if len(key) != 26:
        print(Fore.RED + "[!] Error: Key must be exactly 26 characters.")
        return None
    
    alphabet = 'abcdefghijklmnopqrstuvwxyz'
    key_lower = key.lower()
    
    if len(set(key_lower)) != 26 or not all(c in alphabet for c in key_lower):
        print(Fore.RED + "[!] Error: Key must contain each letter exactly once.")
        return None
    
    decrypted = []
    for char in ciphertext:
        if char.isupper():
            pos = key_lower.index(char.lower())
            decrypted.append(alphabet[pos].upper())
        elif char.islower():
            pos = key_lower.index(char)
            decrypted.append(alphabet[pos])
        else:
            decrypted.append(char)
    return ''.join(decrypted)

# ==================== ORIGINAL BANNER (UNCHANGED) ====================
def print_banner():
    banner = r"""
 ██╗   ██╗██╗ ██████╗ ███████╗███╗   ██╗███████╗██████╗ ███████╗
 ██║   ██║██║██╔════╝ ██╔════╝████╗  ██║██╔════╝██╔══██╗██╔════╝
 ██║   ██║██║██║  ███╗█████╗  ██╔██╗ ██║█████╗  ██████╔╝█████╗
 ╚██╗ ██╔╝██║██║   ██║██╔══╝  ██║╚██╗██║██╔══╝  ██╔══██╗██╔══╝
  ╚████╔╝ ██║╚██████╔╝███████╗██║ ╚████║███████╗██║  ██║███████╗
   ╚═══╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚══════╝

 ===============================================================
        
             Vigenère Cipher Tool - by CHOUAIB
 ===============================================================
    """
    print(Fore.RED + banner)

# ==================== ENHANCED MENU FUNCTIONS ====================
def print_separator():
    print(Fore.BLUE + "=" * 65)

def display_main_menu():
    """Display the main cipher selection menu"""
    print_separator()
    print(Fore.CYAN + Style.BRIGHT + "\n[*] SELECT CIPHER METHOD:")
    print(Fore.GREEN + "  1. Vigenère Cipher    (Polyalphabetic substitution)")
    print(Fore.GREEN + "  2. ROT13 Cipher       (13-letter rotation)")
    print(Fore.GREEN + "  3. Caesar Cipher      (Custom shift cipher)")
    print(Fore.GREEN + "  4. Atbash Cipher      (Alphabet reversal)")
    print(Fore.GREEN + "  5. Substitution Cipher (Custom alphabet mapping)")
    print(Fore.RED + "  0. Quitter (Exit)")
    print_separator()

def vigenere_menu():
    """Original Vigenère cipher menu"""
    while True:
        print(Fore.CYAN + "\n[VIGENÈRE CIPHER]")
        print(Fore.CYAN + "  1. Chiffrer (Encrypt)")
        print(Fore.CYAN + "  2. Déchiffrer (Decrypt)")
        print(Fore.CYAN + "  3. Retour (Back to main menu)")
        choice = input(Fore.GREEN + "[?] Choose an option (1/2/3): ").strip()

        if choice == '1':
            text = input(Fore.GREEN + "[?] Enter the text to encrypt: ").strip()
            key = input(Fore.GREEN + "[?] Enter the key: ").strip()
            result = vigenere_encrypt(text, key)
            if result is not None:
                print(Fore.YELLOW + "[+] Encrypted: " + Fore.WHITE + result)
        elif choice == '2':
            text = input(Fore.GREEN + "[?] Enter the text to decrypt: ").strip()
            key = input(Fore.GREEN + "[?] Enter the key: ").strip()
            result = vigenere_decrypt(text, key)
            if result is not None:
                print(Fore.YELLOW + "[+] Decrypted: " + Fore.WHITE + result)
        elif choice == '3':
            break
        else:
            print(Fore.RED + "[!] Invalid choice. Please try again.")

def rot13_menu():
    """ROT13 cipher menu"""
    while True:
        print(Fore.CYAN + "\n[ROT13 CIPHER]")
        print(Fore.CYAN + "  1. Chiffrer/Déchiffrer (Encrypt/Decrypt)")
        print(Fore.CYAN + "  2. Retour (Back to main menu)")
        choice = input(Fore.GREEN + "[?] Choose an option (1/2): ").strip()

        if choice == '1':
            text = input(Fore.GREEN + "[?] Enter the text: ").strip()
            result = rot13_cipher(text)
            print(Fore.YELLOW + "[+] Result: " + Fore.WHITE + result)
        elif choice == '2':
            break
        else:
            print(Fore.RED + "[!] Invalid choice. Please try again.")

def caesar_menu():
    """Caesar cipher menu"""
    while True:
        print(Fore.CYAN + "\n[CAESAR CIPHER]")
        print(Fore.CYAN + "  1. Chiffrer (Encrypt)")
        print(Fore.CYAN + "  2. Déchiffrer (Decrypt)")
        print(Fore.CYAN + "  3. Retour (Back to main menu)")
        choice = input(Fore.GREEN + "[?] Choose an option (1/2/3): ").strip()

        if choice == '1':
            text = input(Fore.GREEN + "[?] Enter the text to encrypt: ").strip()
            shift = input(Fore.GREEN + "[?] Enter the shift (number): ").strip()
            result = caesar_encrypt(text, shift)
            if result is not None:
                print(Fore.YELLOW + "[+] Encrypted: " + Fore.WHITE + result)
        elif choice == '2':
            text = input(Fore.GREEN + "[?] Enter the text to decrypt: ").strip()
            shift = input(Fore.GREEN + "[?] Enter the shift (number): ").strip()
            result = caesar_decrypt(text, shift)
            if result is not None:
                print(Fore.YELLOW + "[+] Decrypted: " + Fore.WHITE + result)
        elif choice == '3':
            break
        else:
            print(Fore.RED + "[!] Invalid choice. Please try again.")

def atbash_menu():
    """Atbash cipher menu"""
    while True:
        print(Fore.CYAN + "\n[ATBASH CIPHER]")
        print(Fore.CYAN + "  1. Chiffrer/Déchiffrer (Encrypt/Decrypt)")
        print(Fore.CYAN + "  2. Retour (Back to main menu)")
        choice = input(Fore.GREEN + "[?] Choose an option (1/2): ").strip()

        if choice == '1':
            text = input(Fore.GREEN + "[?] Enter the text: ").strip()
            result = atbash_cipher(text)
            print(Fore.YELLOW + "[+] Result: " + Fore.WHITE + result)
        elif choice == '2':
            break
        else:
            print(Fore.RED + "[!] Invalid choice. Please try again.")

def substitution_menu():
    """Substitution cipher menu"""
    while True:
        print(Fore.CYAN + "\n[SUBSTITUTION CIPHER]")
        print(Fore.YELLOW + "[i] Key must be 26 unique letters (e.g., 'zyxwvutsrqponmlkjihgfedcba')")
        print(Fore.CYAN + "  1. Chiffrer (Encrypt)")
        print(Fore.CYAN + "  2. Déchiffrer (Decrypt)")
        print(Fore.CYAN + "  3. Retour (Back to main menu)")
        choice = input(Fore.GREEN + "[?] Choose an option (1/2/3): ").strip()

        if choice == '1':
            text = input(Fore.GREEN + "[?] Enter the text to encrypt: ").strip()
            key = input(Fore.GREEN + "[?] Enter the key (26 letters): ").strip()
            result = substitution_encrypt(text, key)
            if result is not None:
                print(Fore.YELLOW + "[+] Encrypted: " + Fore.WHITE + result)
        elif choice == '2':
            text = input(Fore.GREEN + "[?] Enter the text to decrypt: ").strip()
            key = input(Fore.GREEN + "[?] Enter the key (26 letters): ").strip()
            result = substitution_decrypt(text, key)
            if result is not None:
                print(Fore.YELLOW + "[+] Decrypted: " + Fore.WHITE + result)
        elif choice == '3':
            break
        else:
            print(Fore.RED + "[!] Invalid choice. Please try again.")

def main():
    print_banner()
    
    while True:
        display_main_menu()
        choice = input(Fore.GREEN + "[?] Choose a cipher method (0-5): ").strip()

        if choice == '1':
            vigenere_menu()
        elif choice == '2':
            rot13_menu()
        elif choice == '3':
            caesar_menu()
        elif choice == '4':
            atbash_menu()
        elif choice == '5':
            substitution_menu()
        elif choice == '0':
            print(Fore.YELLOW + "[+] Goodbye!")
            break
        else:
            print(Fore.RED + "[!] Invalid choice. Please try again.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[+] Goodbye!")
    except Exception as e:
        print(Fore.RED + f"\n[!] Error: {e}")
