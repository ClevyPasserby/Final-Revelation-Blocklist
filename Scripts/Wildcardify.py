import tkinter as tk
from tkinter import filedialog

def open_file_dialog():
    # Open a file dialog to select a text file
    file_path = filedialog.askopenfilename(title="Select a Text File", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
    
    if file_path:
        process_file(file_path)

def process_file(file_path):
    # Read the content of the selected file
    try:
        with open(file_path, 'r') as file:
            domains = file.readlines()

        # Modify each domain by adding '*.' in front
        modified_domains = ['*.' + domain.strip() for domain in domains]

        # Write the modified domains to a new file
        with open('modified.txt', 'w') as modified_file:
            for domain in modified_domains:
                modified_file.write(domain + '\n')

        print("Modified domains have been saved to 'modified.txt'")
    except Exception as e:
        print(f"Error: {str(e)}")

# Set up the main application window
root = tk.Tk()
root.title("Domain Modifier")
root.geometry("300x150")

# Create a button to open the file dialog
select_file_button = tk.Button(root, text="Select a Text File", command=open_file_dialog)
select_file_button.pack(pady=20)

# Start the Tkinter event loop
root.mainloop()
