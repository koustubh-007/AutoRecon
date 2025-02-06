import subprocess

def command_exists(command):
    """Check if a command exists on the system."""
    return subprocess.call(f"type {command}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0
  
def printResult(tool):
    if command_exists(tool):
      print(f"[+] {tool} is installed... ")
    else:
        print(f"[!] {tool} is not installed!")
      

print("[+] Checking if the Required Tools are installed or not!...")
tools = ['subfinder', 'assetfinder', 'sublist3r', 'curl', 'amass', 'httpx', 'tee', 'waybackurls', 'gau', 'katana', 'nuclei']

for tool in tools:
    printResult(tool)
