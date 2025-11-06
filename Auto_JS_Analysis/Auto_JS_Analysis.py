import os
import sys
import argparse
from termcolor import colored


def print_colored(message, color, attrs=None):
    print(colored(message, color, attrs=attrs))


def append_to_file(output, file_path):
    with open(file_path, "a") as f:
        f.write(output + "\n")


# ────────────────────────────────────────────────
# NEW: Collect all JS files from a folder recursively
def collect_js_files(folder_path):
    js_files = []
    valid_extensions = {".js", ".ts", ".mjs", ".jsx", ".tsx"}
    
    for root, _, files in os.walk(folder_path):
        for f in files:
            if any(f.lower().endswith(ext) for ext in valid_extensions):
                js_files.append(os.path.join(root, f))
                
    return js_files
# ────────────────────────────────────────────────


# The function to automate the java script links
def process_links(file_path, output_dir):
    
    if not os.path.exists(file_path):
        print_colored(f"Error: File '{file_path}' not found!", "red")
        sys.exit(1)

    with open(file_path, "r") as f:
        links = [line.strip() for line in f.readlines() if line.strip()]

    if not links:
        print_colored(f"Error: No links found in the file '{file_path}'!", "yellow")
        sys.exit(1)

    # Create the output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    # Output file paths
    linkfinder_output_file = os.path.join(output_dir, "linkfinder_results.txt")
    secretfinder_output_file = os.path.join(output_dir, "secretfinder_results.txt")

    open(linkfinder_output_file, "w").close()
    open(secretfinder_output_file, "w").close()

    # Process each link
    for index, link in enumerate(links, 1):
        print_colored(f"\nProcessing ({index}/{len(links)}): {link}", "cyan", attrs=["bold"])

        # Run LinkFinder
        print_colored("\nRunning LinkFinder...", "green")
        linkfinder_cmd = f"python3 LinkFinder/linkfinder.py -i {link} -o cli"
        linkfinder_result = os.popen(linkfinder_cmd).read()
        print(linkfinder_result)
        append_to_file(f"Results for {link}:\n{linkfinder_result}\n{'-'*80}\n", linkfinder_output_file)

        # Run SecretFinder
        print_colored("\nRunning SecretFinder...", "blue")
        secretfinder_cmd = f"python3 SecretFinder/SecretFinder.py -i {link} -o cli"
        secretfinder_result = os.popen(secretfinder_cmd).read()
        print(secretfinder_result)
        append_to_file(f"Results for {link}:\n{secretfinder_result}\n{'-'*80}\n", secretfinder_output_file)

    # Final message
    print_colored("\nAll results saved!", "yellow", attrs=["bold"])
    print_colored(f"- LinkFinder results: {linkfinder_output_file}", "green")
    print_colored(f"- SecretFinder results: {secretfinder_output_file}", "blue")


# ────────────────────────────────────────────────
# NEW: Process all JS files in a folder tree
def process_folder(folder_path, output_dir):
    js_files = collect_js_files(folder_path)
    if not js_files:
        print_colored(f"No JavaScript files found in {folder_path}", "red")
        sys.exit(1)

    print_colored(f"Found {len(js_files)} JavaScript files.", "yellow")

    # Write them temporarily to a list file
    temp_file = os.path.join(output_dir, "js_file_list.txt")
    os.makedirs(output_dir, exist_ok=True)
    with open(temp_file, "w") as f:
        for js in js_files:
            f.write(js + "\n")

    # Reuse the existing process_links() logic
    process_links(temp_file, output_dir)
# ────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(description="Process JavaScript links or local JS files with LinkFinder and SecretFinder.")
    parser.add_argument("-i", "--input", help="Path to a file containing JavaScript links (URLs).")
    parser.add_argument("-f", "--folder", help="Path to a folder containing many JavaScript files to scan recursively.")
    parser.add_argument("-o", "--output", required=True, help="Directory to save the result files.")
    args = parser.parse_args()

    if args.input:
        process_links(args.input, args.output)
    elif args.folder:
        process_folder(args.folder, args.output)
    else:
        print_colored("Error: Please provide either --input (for link list) or --folder (for JS directory).", "red")
        sys.exit(1)


if __name__ == "__main__":
    main()
