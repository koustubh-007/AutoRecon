# AutoRecon API-only mode

## Kali Linux / WSL2 setup

From the cloned repository directory (normally `~/AutoRecon`), run:

```bash
python3 setup.py
```

The bootstrapper checks/installs required apt packages, creates the project-local `.venv`, installs Python dependencies and Python CLI tools into that environment, installs missing Go recon binaries, and prints a final status summary with the virtual environment path. It may ask for your sudo password when apt packages are missing. It does not run any recon scans. Amass is intentionally not installed because its enumeration step was removed.

Activate the environment for later sessions:

```bash
source .venv/bin/activate
```

If setup reports failures, fix those specific items and rerun `python3 setup.py`.

API mode is separate from the existing general recon path. It loads the selected hosts, reads compatible local recon output files, discovers likely OpenAPI/Swagger documents, parses endpoint metadata, supplements routes from URL/JavaScript strings, and writes a normalized inventory.

## General recon: out-of-scope filtering

Use \`-os\` with a text file containing one excluded domain per line. Blank lines and lines beginning with \`#\` are ignored. Entries can be hostnames, URLs, or wildcard-prefixed domains such as \`*.staging.example.com\`.

\`\`\`bash
python autoRecon.py -d example.com -os out_of_Scope_domains.txt
python autoRecon.py -l domains.txt -os out_of_Scope_domains.txt
\`\`\`

AutoRecon applies the exclusions when building \`all_subdomains.txt\`, before HTTP probing and URL collection. An excluded domain also excludes its subdomains. Matching uses hostname boundaries: excluding \`staging.example.com\` does not exclude \`notstaging.example.com\`.

The `-os` option is optional. If the flag is omitted, recon runs normally without filtering. If `-os` is supplied without a path, or its path does not exist or cannot be read, AutoRecon prints an error and terminates before enumeration. The raw tool result files are retained for traceability; the filtered `all_subdomains.txt` is the list consumed by later stages when filtering is enabled.

## API mode usage

Run from the repository root:

\`\`\`bash
python autoRecon.py --api example.com/api.domains.txt
\`\`\`

Choose a custom output folder:

\`\`\`bash
python autoRecon.py --api example.com/api.domains.txt --output results/api_run_01
\`\`\`

When the project is installed as a package, the same commands can use the \`autorecon\` console entry point:

\`\`\`bash
python -m pip install -e .
autorecon --api example.com/api.domains.txt --output results/api_run_01
\`\`\`

Optional broader authorized scope:

\`\`\`bash
python autoRecon.py --api example.com/api.domains.txt --scope authorized_roots.txt
\`\`\`

Optional, low-volume GET/HEAD reachability observations:

\`\`\`bash
python autoRecon.py --api example.com/api.domains.txt --validate
\`\`\`

Install only the API-mode Python dependencies if you don't want an editable package install:

\`\`\`bash
python -m pip install -r requirements-api.txt
\`\`\`

## General recon integration

After the existing general recon finishes, AutoRecon writes:

- \`<target>/api_candidates.txt\`: heuristic API-host candidates.
- \`<target>/api.domains.txt\`: initialized from candidates only if the file does not already exist.

Review and edit \`api.domains.txt\` before API mode. Rerunning general recon does not overwrite a previously edited selection file.

## API-mode output

\`\`\`text
results/api_recon/
├── api.domains.txt
├── api_candidates.txt
├── discovered_specs.json
├── spec_candidates.txt
├── specs/
├── api_endpoints.json
├── api_endpoints.txt
├── api_endpoints.csv
├── discovered_urls.txt
├── javascript/
│   ├── js_urls.txt
│   └── extracted_endpoints.txt
├── report.md
├── invalid_inputs.txt
└── logs/
    ├── api_recon.log
    └── spec_errors.txt          # created only when request errors occur
\`\`\`

With \`--validate\`, \`validation_results.json\` is also created.

## Safety and interpretation

- Only hosts covered by the selected target list or optional scope roots are fetched.
- Redirects are not followed during discovery or optional validation.
- Specification response size, request timeouts, and request counts are bounded.
- External OpenAPI \`$ref\` documents are not recursively fetched.
- Optional validation is limited to low-volume GET/HEAD observations.
- Endpoint candidates and status codes are evidence, not vulnerability findings. Manually verify authorization and business logic with program-authorized accounts.
- API-host candidate detection is heuristic. Review scope and edit the selection list before use.
