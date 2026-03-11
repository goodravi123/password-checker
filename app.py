import os
import webbrowser
import tempfile

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

    print("[NO MATCH] Password not found in any file.")
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

# Example usage
if __name__ == "__main__":
    password_to_check = input("Enter the password to scan: ")
    path_to_folder = input("Enter the path to the folder containing password lists: ")
    
    if not os.path.exists(path_to_folder):
        print("Invalid folder path. Please provide a valid path.")
    else:
        scan_password(password_to_check, path_to_folder)