import os
import webbrowser
import tempfile
import base64
import binascii
import re

# common online password lists (raw GitHub URLs or similar)
# users can add their own, or rely on these defaults
DEFAULT_ONLINE_LISTS = [
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt",
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/20k-most-common.txt",
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/100k-most-common.txt",
    "https://raw.githubusercontent.com/berandal666/Passwords/refs/heads/master/10_million_password_list_top_1000000.txt"   
    # other sources may be added here as desired
]

def decode_password(encoded):
    """Attempt to decode an encoded password string.

    This helper performs a best-effort attempt using a variety of common
    encodings/formats.  It returns the first decoded value that appears to
    be a valid UTF‑8 string; otherwise the original input is returned.

    Currently the following strategies are tried, in order:

    1. **Hexadecimal** (plain `0-9a-f` pairs)
    2. **URL percent‑encoding** (``urllib.parse.unquote``)
    3. **ASCII numerical lists** – a sequence of integer values
       separated by spaces or commas, interpreted as character codes
       (bytes or Unicode code points).
    4. **Base64** (with automatic padding correction)
    5. **ROT13** transformation (only letters-only inputs are considered)

    Additional encodings may be added in the future.
    """
    # helper to check if decoded text is nonempty, printable, and ASCII
    def _valid_text(s: str) -> bool:
        # require at least one character
        if not s:
            return False
        # all characters should be ASCII printable (excluding control/high-bit)
        for ch in s:
            o = ord(ch)
            if o < 32 or o >= 127 or not ch.isprintable():
                return False
        return True

    # 1. hex – test first because hex strings are also valid base64
    try:
        decoded_bytes = bytes.fromhex(encoded)
        decoded = decoded_bytes.decode("utf-8", errors="ignore")
        if _valid_text(decoded):
            return decoded
    except Exception:
        pass

    # 2. URL‑percent decoding
    try:
        from urllib.parse import unquote

        decoded = unquote(encoded)
        if decoded != encoded and _valid_text(decoded):
            return decoded
    except Exception:
        pass

    # 3. ascii codes separated by space/comma
    try:
        parts = [p for p in re.split(r"[\s,]+", encoded.strip()) if p]
        if parts and all(p.isdigit() for p in parts):
            chars = [chr(int(p)) for p in parts]
            decoded = "".join(chars)
            if _valid_text(decoded):
                return decoded
    except Exception:
        pass

    # 4. base64 – decode after the simpler formats
    try:
        padding = len(encoded) % 4
        if padding:
            encoded_mod = encoded + "=" * (4 - padding)
        else:
            encoded_mod = encoded
        decoded_bytes = base64.b64decode(encoded_mod, validate=True)
        decoded = decoded_bytes.decode("utf-8", errors="ignore")
        if _valid_text(decoded):
            return decoded
    except Exception:
        pass

    # 5. rot13 – only if the string is letters-only (avoids colliding with base64)
    try:
        if re.fullmatch(r"[A-Za-z]+", encoded):
            import codecs

            decoded = codecs.decode(encoded, "rot_13")
            if decoded != encoded and _valid_text(decoded):
                return decoded
    except Exception:
        pass

    # fallback – return original
    return encoded

def scan_password(password, folder_path):
    """
    Function to scan a given password against password lists in a folder.
    
    Args:
        password (str): The password to check.
        folder_path (str): The path to the folder containing the password lists.
    """
    # Iterate over all files in the given folder
    for file_name in os.listdir(folder_path):
        file_path = os.path.join(folder_path, file_name)

        # Check if it is a file (and not a directory)
        if os.path.isfile(file_path):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                    print(f"Scanning in file: {file_name}")
                    # Search each line for the password
                    line_number = 0
                    for line in file:
                        line_number += 1
                        if password == line.strip():
                            print(f"[MATCH FOUND] Password '{password}' found in file: {file_name} at line {line_number}")
                            display_file_with_highlight(file_path, password, line_number)
                            return True
            except Exception as e:
                print(f"Error reading file {file_name}: {e}")

    # no match in local files
    return False

def display_file_with_highlight(file_path, password, line_number):
    """
    Display the file content in a browser with the matched password highlighted.
    
    Args:
        file_path (str): Path to the file containing the password.
        password (str): The password to highlight.
        line_number (int): The line number where the password was found.
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            lines = file.readlines()
        
        # Create HTML content with highlighted password
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Password Found - {os.path.basename(file_path)}</title>
            <style>
                body {{ font-family: monospace; background-color: #f5f5f5; padding: 20px; }}
                .container {{ background-color: white; padding: 20px; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
                .line {{ padding: 5px; margin: 2px 0; }}
                .highlight {{ background-color: yellow; font-weight: bold; }}
                .match-line {{ background-color: #fff3cd; border-left: 3px solid #ffc107; padding-left: 10px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h2>Password Match Found!</h2>
                <p><strong>File:</strong> {os.path.basename(file_path)}</p>
                <p><strong>Password:</strong> <span class="highlight">{password}</span></p>
                <p><strong>Location:</strong> Line {line_number}</p>
                <hr>
                <h3>File Content:</h3>
                <pre>
        """
        
        # Add lines with highlighting
        for i, line in enumerate(lines, 1):
            if i == line_number:
                highlighted_line = line.rstrip().replace(password, f'<span class="highlight">{password}</span>')
                html_content += f'<div class="line match-line"><strong>{i}:</strong> {highlighted_line}</div>\n'
            else:
                html_content += f'<div class="line"><strong>{i}:</strong> {line.rstrip()}</div>\n'
        
        html_content += """
                </pre>
            </div>
        </body>
        </html>
        """
        
        # Write to temporary file and open in browser
        with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as temp_file:
            temp_file.write(html_content)
            temp_file_path = temp_file.name
        
        webbrowser.open('file://' + temp_file_path)
        print(f"Displaying file content in browser...")
    except Exception as e:
        print(f"Error displaying file: {e}")

# online scanning helpers

def scan_url(password, url):
    """Fetch a text file from *url* and look for *password* in its lines.

    Returns True on first match.
    """
    try:
        from urllib.request import urlopen
        resp = urlopen(url, timeout=15)
        line_num = 0
        for raw in resp:
            line_num += 1
            try:
                line = raw.decode("utf-8", errors="ignore").strip()
            except Exception:
                continue
            if password == line:
                print(f"[MATCH FOUND] Password '{password}' found in online list: {url} (line {line_num})")
                return True
    except Exception as e:
        print(f"Error fetching {url}: {e}")
    return False


def scan_online_passwords(password, urls):
    """Try a sequence of URLs containing password lists.

    The *urls* argument may be a list of raw Github URLs or any plain-text
    resource.  The function downloads each resource and checks it line by
    line.  It prints progress and stops on the first positive hit.
    """
    print("\nChecking online password lists...")
    for url in urls:
        print(f"  -> {url}")
        if scan_url(password, url):
            return True
    print("[NO MATCH] Password not found in any online list.")
    return False

# helper for user interaction

def ask_yes_no(prompt: str) -> bool:
    """Prompt with *prompt* and return True for yes, False for no.

    Repeats until the user answers with something starting with 'y' or 'n'.
    """
    while True:
        ans = input(prompt + " (y/n): ").strip().lower()
        if not ans:
            continue
        if ans[0] == "y":
            return True
        if ans[0] == "n":
            return False
        print("Please answer 'y' or 'n'.")


# Example usage
if __name__ == "__main__":
    password_to_check = input("Enter the password to scan: ")

    # explicitly ask if the input is encoded
    if ask_yes_no("Is it encoded?"):
        decoded_value = decode_password(password_to_check)
        if decoded_value != password_to_check:
            print(f"Decoded to '{decoded_value}'")
            password_to_check = decoded_value
        else:
            print("Decoding attempt produced no change.")

    path_to_folder = input("Enter the path to the folder containing password lists: ")

    if not os.path.exists(path_to_folder):
        print("Invalid folder path. Please provide a valid path.")
        found = False
    else:
        found = scan_password(password_to_check, path_to_folder)

    # if local search didn't produce a hit, ask about online lists
    if not found and ask_yes_no("Search some common online password lists?"):
        urls = list(DEFAULT_ONLINE_LISTS)  # copy
        extra = input("Enter additional list URLs (comma-separated) or press Enter to use defaults: ").strip()
        if extra:
            urls.extend([u.strip() for u in extra.split(",") if u.strip()])
        scan_online_passwords(password_to_check, urls)

    # if running in a standalone cmd window, keep it open until user closes
    try:
        input("\nPress Enter to exit... ")
    except Exception:
        pass