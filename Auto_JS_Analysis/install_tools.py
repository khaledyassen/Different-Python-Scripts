import os
import subprocess
import sys

# Function to print colored messages
def print_message(message, color="green"):
    try:
        from termcolor import colored
        print(colored(message, color))
    except ImportError:
        print(message)

# Function to run a shell command
def run_command(command, error_message):
    try:
        subprocess.check_call(command, shell=True)
    except subprocess.CalledProcessError:
        print_message(error_message, "red")
        sys.exit(1)

# Function to install required Python package
def install_python_package(package):
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package, "--break-system-packages"])
    except subprocess.CalledProcessError:
        print_message(f"Failed to install {package}. Please install it manually.", "red")
        sys.exit(1)

# Main installation process
def install_tools():
    # Check for Git
    if not shutil.which("git"):
        print_message("Error: Git is not installed. Please install Git and try again.", "red")
        sys.exit(1)

    # Install termcolor
    print_message("Installing 'termcolor' package for colored output...")
    install_python_package("termcolor")

    # Clone LinkFinder
    print_message("Cloning LinkFinder repository...")
    if not os.path.exists("LinkFinder"):
        run_command("git clone https://github.com/GerbenJavado/LinkFinder.git", "Failed to clone LinkFinder repository.")
    else:
        print_message("LinkFinder repository already exists. Skipping cloning.", "yellow")

    # Install LinkFinder dependencies
    print_message("Installing LinkFinder dependencies...")
    run_command("pip install -r LinkFinder/requirements.txt --break-system-packages", "Failed to install LinkFinder dependencies.")

    # Clone SecretFinder
    print_message("Cloning SecretFinder repository...")
    if not os.path.exists("SecretFinder"):
        run_command("git clone https://github.com/m4ll0k/SecretFinder.git", "Failed to clone SecretFinder repository.")
    else:
        print_message("SecretFinder repository already exists. Skipping cloning.", "yellow")

    # Install SecretFinder dependencies
    print_message("Installing SecretFinder dependencies...")
    run_command("pip install -r SecretFinder/requirements.txt --break-system-packages", "Failed to install SecretFinder dependencies.")

    # Finish message
    print_message("\nInstallation complete!")
    print_message("LinkFinder and SecretFinder are now ready to use.", "cyan")

# Run the script
if __name__ == "__main__":
    import shutil

    try:
        install_tools()
    except Exception as e:
        print_message(f"An unexpected error occurred: {str(e)}", "red")
        sys.exit(1)
