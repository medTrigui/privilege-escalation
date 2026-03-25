# PrivEsc

A comprehensive Jekyll-based reference for Linux and Windows privilege escalation techniques, tradecraft, and exploitation patterns.

## Live Project

- https://medtrigui.github.io/privilege-escalation/

## Features

- **Clean, responsive theme** - Optimized for security documentation
- **Organized structure** - Systematic Linux and Windows privilege escalation guides
- **External tool integration** - Direct links to GTFOBins, Escabin, and SearchSploit
- **Jekyll-powered** - Fast, static site generation
- **Generalized examples** - Reference patterns applicable across diverse environments

## Quick Start

### Prerequisites

- Ruby 3.0+
- Bundler

### Installation & Development

```bash
# Install dependencies
bundle install

# Build the site
bundle exec jekyll build

# Serve locally with auto-reload
bundle exec jekyll serve
```

The site will be available at `http://localhost:4000`

## Directory Structure

```
.
├── _config.yml                 # Jekyll configuration
├── _docs/                      # Documentation collection
│   ├── linux-privilege-escalation.md
│   └── windows-privilege-escalation.md
├── _layouts/                   # Page templates
│   ├── default.html
│   └── page.html
├── _includes/                  # Reusable components
│   ├── header.html
│   └── footer.html
├── assets/css/                 # Stylesheets
│   └── style.css               # Clean, minimal theme
├── index.md                    # Homepage
├── Gemfile                     # Ruby dependencies
└── _site/                      # Generated static site
```

## Content Organization

### Linux Privilege Escalation

1. **Enumerating Linux** - Systematic manual and automated enumeration
   - Privilege model basics
   - Manual enumeration workflow
   - Automated tools (unix-privesc-check, LinEnum, LinPEAS)

2. **Exposed Confidential Information** - Credential harvesting techniques
   - User trails & shell artifacts
   - System trails & live telemetry

3. **Insecure File Permissions** - Exploiting writable files
   - Writable scheduled jobs
   - Authentication store injection

4. **Insecure System Components** - Privilege boundary exploitation
   - SUID programs & capabilities
   - Sudo misconfigurations
   - Kernel vulnerabilities

### Windows Privilege Escalation

Similar structured approach covering Windows-specific vectors.

## Key Resources

- **[GTFOBins](https://gtfobins.org/)** - SUID/Capability binary exploitation
- **[Escabin](https://medtrigui.github.io/escabin/)** - Extended GTFOBins reference
- **[SearchSploit](https://www.exploit-db.com/)** - Exploit database

## Design Principles

- **Tradecraft-focused** - Repeatable techniques across environments
- **Recon-driven** - Thorough enumeration before advanced exploitation
- **Generalized examples** - Reference patterns, not lab-specific walkthroughs
- **Tool integration** - Cross-reference with external exploit databases

## Building for Production

```bash
# Build optimized static site
bundle exec jekyll build --no-watch

# The site is ready to serve from the _site/ directory
# Deploy to any static hosting (GitHub Pages, Netlify, etc.)
```

## Deployment Options

### GitHub Pages

```bash
# Push to gh-pages branch
git subtree push --prefix _site origin gh-pages
```

### Static Hosting

Simply push the `_site/` directory to any web server or static hosting platform.

## Contributing

Contributions welcome! Areas for expansion:

- macOS privilege escalation techniques
- Container/Kubernetes escalation
- Advanced kernel exploitation patterns
- Additional real-world case studies

## Disclaimer

This material is for authorized security testing and educational purposes only. Unauthorized access to computer systems is illegal. Always obtain written permission before conducting security assessments.

## License

See LICENSE file for details.

## Author

Created as a comprehensive reference for security professionals and penetration testers.
