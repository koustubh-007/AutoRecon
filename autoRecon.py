import os
import subprocess
import sys
import dirsearch


def command_exists(command):
    """Check if a command exists on the system."""
    return subprocess.call(f"type {command}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0


def run_command(command):
    """Run a system command and return the output."""
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout.strip()


def print_count(domain, command):
    count = run_command(f"cat {domain}/{command}.txt | wc -l")
    print(f"[*] {command}: {count}")


def process_domain(domain):
    print(f"[+] Processing domain: {domain}")

    # Create a directory for the domain's results
    os.makedirs(domain, exist_ok=True)

    # Enumerate subdomains using subfinder
    if command_exists("subfinder"):
        print("[+] Running subfinder...")
        output = run_command(f"subfinder -d {domain} -all --recursive -silent")
        with open(f"{domain}/subfinder.txt", "w") as f:
            f.write(output)
        print_count(domain, 'subfinder')
    else:
        print("[!] subfinder not found!")

    # Enumerate subdomains using assetfinder
    if command_exists("assetfinder"):
        print("[+] Running assetfinder...")
        output = run_command(f"assetfinder --subs-only {domain}")
        with open(f"{domain}/assetfinder.txt", "w") as f:
            f.write(output)
        print_count(domain, 'assetfinder')
    else:
        print("[!] assetfinder not found!")

    # Enumerate subdomains using Sublist3r
    if command_exists("sublist3r"):
        print("[+] Running Sublist3r...")
        output = run_command(f"sublist3r -d {domain} -o {domain}/sublist3r.txt")
        print_count(domain, 'sublist3r')
    else:
        print("[!] Sublist3r not found!")

    # Enumerate subdomains using crt.sh
    print("[+] Querying crt.sh...")
    crtsh_output = run_command(
        f"curl -s 'https://crt.sh/?q=%25.{domain}&output=json' | jq -r '.[].name_value' | sed 's/\\*\\.//g' | sort -u")
    with open(f"{domain}/crtsh.txt", "w") as f:
        f.write(crtsh_output)
    print_count(domain, 'crtsh')

    # Enumerate subdomains using amass
    if command_exists("amass"):
        print("[+] Running amass with a 3-hour limit...")
        output = run_command(f"timeout 3h amass enum -brute -active -d {domain}")
        if output == "":
            print("[!] amass timed out after 3 hours.")
        else:
            print("[+] Amass ran sucessfully!")
        with open(f"{domain}/amass.txt", "w") as f:
            f.write(output)
        print_count(domain, 'amass')
    else:
        print("[!] amass not found!")

    # Combine all subdomains, sort and remove duplicates
    print("[+] Combining subdomain results...")
    combined_subdomains = run_command(f"cat {domain}/*.txt | sort -u | tee {domain}/all_subdomains.txt")

    print(f"[+] Found {len(combined_subdomains.splitlines())} unique subdomains.")
    print(f"[+] Results saved to {domain}/all_subdomains.txt")

    # Check HTTP status codes using httpx

    if command_exists("httpx"):
        print("[+] Running httpx to check status codes...")
        httpx_output = run_command(
            f"httpx -silent -status-code -l {domain}/all_subdomains.txt -o {domain}/all_codes.txt")

        # Extracting URLs with status code 200

        os.makedirs(f"{domain}/httpx", exist_ok=True)
        urls_with_200 = run_command(
            f"grep '200' {domain}/all_codes.txt | awk '{{print $1}}' | tee {domain}/httpx/200.txt ")
        urls_with_300 = run_command(
            f"grep -E '301|302'  {domain}/all_codes.txt | awk '{{print $1}}' | tee {domain}/httpx/300.txt ")
        urls_with_403 = run_command(
            f"grep '403' {domain}/all_codes.txt | awk '{{print $1}}' | tee {domain}/httpx/403.txt ")
        urls_with_404 = run_command(
            f"grep '404' {domain}/all_codes.txt | awk '{{print $1}}' | tee {domain}/httpx/404.txt ")

        # Printing the output of each type of URLs

        print(f"[+] Saved subdomains with status code 200 to {domain}/httpx/200.txt")
        print(f"[+] Saved subdomains with status code 300 to {domain}/httpx/300.txt")
        print(f"[+] Saved subdomains with status code 403 to {domain}/httpx/403.txt")
        print(f"[+] Saved subdomains with status code 404 to {domain}/httpx/404.txt")

    else:
        print("[!] httpx not found!")

    # Find URLs using waybackurls

    if command_exists("waybackurls"):
        print("[+] Running waybackurls...")
        waybackurls_output = run_command(f"cat {domain}/all_subdomains.txt | waybackurls")
        with open(f"{domain}/waybackurls.txt", "w") as f:
            f.write(waybackurls_output)
        print_count(domain, 'waybackurls')
    else:
        print("[!] waybackurls not found!")

    # Find URLs using gau

    if command_exists("gau"):
        print("[+] Running gau...")
        gau_output = run_command(f"gau {domain}")
        with open(f"{domain}/gau.txt", "w") as f:
            f.write(gau_output)
        print_count(domain, 'gau')
    else:
        print("[!] gau not found!")

    # Find URLs using katana

    if command_exists("katana"):
        print("[+] Running katana...")
        katana_output = run_command(f"katana -list {domain}/all_subdomains.txt -silent -o {domain}/katana.txt")
        with open(f"{domain}/katana.txt", "w") as f:
            f.write(katana_output)
        print_count(domain, 'katana')
    else:
        print("[!] katana not found!")

    # Combine all URLs found by the tools, sort and remove duplicates

    print("[+] Combining all URLs found...")
    combined_urls = run_command(f"cat {domain}/waybackurls.txt {domain}/gau.txt {domain}/katana.txt | sort -u")
    with open(f"{domain}/all_urls.txt", "w") as f:
        f.write(combined_urls)

    print(f"[+] Found {len(combined_urls.splitlines())} unique URLs.")
    print(f"[+] Results saved to {domain}/all_urls.txt")

    # Extract .js files from URLs with status code 200
    print("[+] Extracting .js files from URLs with status code 200...")
    js_wb_files = run_command(f"cat {domain}/all_urls.txt | httpx -mc 200 | grep .js | tee -a {domain}/js.txt")
    print_count(domain, 'js')

    # Use nuclei to find exposures in .js files
    if command_exists("nuclei"):
        print("[+] Running nuclei on .js files...")
        nuclei_output = run_command(
            f"nuclei -l {domain}/js.txt -t ~/nuclei-templates/http/exposures/ -o {domain}/js_exposures_results.txt")
        print(f"[+] Nuclei results saved to {domain}/js_exposures_results.txt")
        print_count(domain, 'js_exposures_results')
    else:
        print("[!] nuclei not found!")

    # Find potential IDOR vulnerable URLs
    print("[+] Searching for potential IDOR vulnerable URLs...")
    idor_urls = run_command(
        f"grep -E -i '(\\?|&)(id|user_id|account_id|profile_id|order_id|item_id|product_id|uid|pid|cid|token|session)=[0-9]+' {domain}/all_urls.txt")
    with open(f"{domain}/IDOR.txt", "w") as f:
        f.write(idor_urls)
    print(f"[+] Found potential IDOR vulnerable URLs in {domain}/IDOR.txt")
    print_count(domain, 'IDOR')

    # Find potential open redirect vulnerable URLs
    print("[+] Searching for potential open redirect vulnerable URLs...")
    open_redirect_urls = run_command(
        f"grep -E -i '(\\?|&)(next|url|redirect|out|view|redir|target|rurl|link|go|to|ReturnUrl|RedirectUrl|q|link|src|linkAddress|location|burl|request|backurl|RedirectUrl|Redirect|ReturnUrl|allinurl|u|recurl|uri|service|sp_url|action|action_url|redirect|redirecturl|returnurl|u1|page|desturl|origin|originUrl|originurl|jump|jump_url|callback_url|pic|forward|forward_url|rit_url|goto|clickurl|ext|logout|login|qurl|logout|data|success|return_path|continue|checkout_url|return_to|returnTo|return|go|image_url|to|view|out|cgi-bin|redirect.cgi|destination|dest|redirect_uri|redirect_url|out)=(http|https|%2f|@|//)' {domain}/all_urls.txt")
    with open(f"{domain}/open_redirect.txt", "w") as f:
        f.write(open_redirect_urls)
    print_count(domain, 'open_redirect')
    print(f"[+] Found potential open redirect vulnerable URLs in {domain}/open_redirect.txt")

    print(f"[+] Completed processing for domain: {domain}")
    print("------------------------------------------")


def main():
    # Check if a domain list was provided
    global mode, userInput
    if len(sys.argv) < 2:
        print("Usage: python script.py <mode> <domain/list>")
        exit(1)

    try:
        mode = sys.argv[1]
        userInput = sys.argv[2]

    except IndexError:
        print("[!] Insufficient arguments....")
        exit(1)


    try:
        if (mode == "-dir" and userInput in ('-h', '--help')):
            print("[>] use the path : <domain>/httpx/<403/404>.txt")
            print("[>] use only <403/404>.txt as filename in the /httpx/ directory!")
            print("[>] example: example.com/httpx/403.txt")
            print("[>] cmd for dirsearch: python3 Brown-info.py -dir <domain/folder>")
            print("[>] example: python3 Brown-info.py -dir example.com")
        elif mode == "-dir" and userInput != '':
            dirsearch.run_dirsearch(userInput)
    except FileNotFoundError:
        print("[!] File not found or not in the correct directory!...")
        print("[!] Refer the dirsearch help menu ( -dir -h,--help) ")


    if mode == "-d":
        process_domain(userInput)


    if mode == "-l":
        # Read the list of domains
        with open(userInput, 'r') as file:
            domains = file.readlines()
        # Process each domain
        for domain in domains:
            process_domain(domain.strip())


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Keyboard Interrupt detected!")
        print("[+] Quitting!...")
