# AutoRecon API-only mode

API mode is separate from the existing general recon path. It loads the selected hosts, reads compatible local recon output files, discovers likely OpenAPI/Swagger documents, parses endpoint metadata, supplements routes from URL/JavaScript strings, and writes a normalized inventory.

## Usage

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
