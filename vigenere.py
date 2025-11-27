#!/usr/bin/env python3
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def vigenere_encrypt(plaintext, key):
    encrypted = []
    key_length = len(key)
    if key_length == 0:
        print(Fore.RED + "[!] Error: Key cannot be empty.")
        return None
    for i, char in enumerate(plaintext.upper()):
        if char.isalpha():
            shift = ord(key[i % key_length].upper()) - ord('A')
            encrypted_char = chr(((ord(char) - ord('A') + shift) % 26) + ord('A'))
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
    for i, char in enumerate(ciphertext.upper()):
        if char.isalpha():
            shift = ord(key[i % key_length].upper()) - ord('A')
            decrypted_char = chr(((ord(char) - ord('A') - shift) % 26) + ord('A'))
            decrypted.append(decrypted_char)
        else:
            decrypted.append(char)
    return ''.join(decrypted)

def print_banner():
    banner = r"""
   _____ _     _ _     _ _____ _   _ _____ _____ _   _ _____
  /  __ \ |   | | |   | |_   _| | | |_   _|_   _| | | |_   _|
  | /  \/ |__| | | |__| | | | | | | | | |   | | | | | | | |
  | |     |  __  | |  __  | | | | |_| | | |   | | | |_| | | |
  | \__/\| |  | | | |  | |_| |_|  _  | |   _| |_|  _  | | |
   \____/\_|  |_|_|_|  |_/\___/\___/_/ |_|  \___/\___/  |_|
    """
    print(Fore.RED + banner)
    print(Fore.YELLOW + "Vigenère Cipher Tool - by CHOUAIB\n")

def main():
    print_banner()
    while True:
        print(Fore.CYAN + "\n1. Chiffrer (Encrypt)")
        print(Fore.CYAN + "2. Déchiffrer (Decrypt)")
        print(Fore.CYAN + "3. Quitter (Quit)")
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
