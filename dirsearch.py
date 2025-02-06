import subprocess
import os


def command_exists(command):
    """Check if a command exists on the system."""
    return subprocess.call(f"type {command}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0


def run_command(command):
    """Run a system command and return the output."""
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout.strip()


def dirsearch_cmd(in_path, out_path):
    if not command_exists("dirsearch"):
        exit(1)
    extensions = "php,asp,aspx,jsp,py,txt,conf,config,bak,backup,swp,old,db,sql,asp,aspx,py,rb,bak,bkp,cache,cgi,conf,csv,html,inc,jar,js,json,jsp,lock,log,rar,old,sql,sql.gz,tar,tar.gz,txt,wadl,zip"
    return f"python3 dirsearch.py -e {extensions} -l {in_path} -r -o {out_path} -i 200 --full-url"


def run_dirsearch(domain):
        os.makedirs(f"{domain}/dirsearch", exist_ok=True)
        print("[+] Running dirsearch on 403 subdomains...")
        dirsearch_403 = run_command(dirsearch_cmd(f'{domain}/httpx/403.txt', f'{domain}/dirsearch/dirsearch_403.txt'))
        print(f"[+] Dirsearch results saved to httpx/403.txt")

        print("[+] Running dirsearch on 404 subdomains...")
        dirsearch_404 = run_command(dirsearch_cmd(f'{domain}/httpx/404.txt', f'{domain}/dirsearch/dirsearch_404.txt'))
        print(f"[+] Dirsearch results saved to httpx/404.txt")


