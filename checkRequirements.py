import subprocess

def run_command(command):
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout.strip()

def command_exists(command):
    """Check if a command exists on the system."""
    return subprocess.call(f"type {command}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0
  
def printResult(tool):

    ins_cmds = {
    "subfinder": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "assetfinder": "go install github.com/tomnomnom/assetfinder@latest",
    "sublist3r": "pip install git+https://github.com/aboul3la/Sublist3r.git",
    "curl": "sudo apt install curl -y",
    "amass": "go install -v github.com/owasp-amass/amass/v4/...@latest",
    "httpx": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "tee": "sudo apt install coreutils -y",
    "waybackurls": "go install github.com/tomnomnom/waybackurls@latest",
    "gau": "go install github.com/lc/gau/v2/cmd/gau@latest",
    "katana": "go install github.com/projectdiscovery/katana/cmd/katana@latest",
    "nuclei": "go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
   }

    if command_exists(tool):
        print(f"[+] {tool} is installed... ")
    else:
        print(f"[!] {tool} is not installed!")
        print(f"[+] Installing {tool} ...!")
        run_command(ins_cmds[tool])
        
      

print("[+] Checking if the Required Tools are installed or not!...")

tools = ['subfinder', 'assetfinder', 'sublist3r', 'curl', 'amass', 'httpx', 'tee', 'waybackurls', 'gau', 'katana', 'nuclei']

for tool in tools:
    print("[+] Enter your sudo Passwd: ")
    run_command("sudo su")
    printResult(tool)
