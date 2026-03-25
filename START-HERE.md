# Jekyll Site Build Instructions

## Quick Start

```bash
cd /workspaces/privilege-escalation
bundle install
bundle exec jekyll serve
```

Visit http://localhost:4000 to view the site.

## Available Commands

- `bundle exec jekyll build` - Build static site to _site/
- `bundle exec jekyll serve` - Serve locally at http://localhost:4000
- `bundle exec jekyll build --incremental` - Faster incremental builds during development

## Site Structure

- **/ (index.md)** - Homepage with navigation to Linux and Windows guides
- **/docs/linux-privilege-escalation/** - Linux privilege escalation techniques
- **/docs/windows-privilege-escalation/** - Windows privilege escalation techniques
- **/assets/css/** - Minimal, responsive CSS theme

## Key Features

✅ Generalized examples (no specific usernames, timestamps, or paths)  
✅ GTFOBins and Escabin links throughout for SUID/capability exploitation  
✅ Clean, minimal Jekyll theme optimized for security documentation  
✅ Organized flow with clear sections and subsections  
✅ Responsive design for desktop and mobile  

## Building for Publishing

```bash
# Clean build
rm -rf _site
bundle exec jekyll build

# Output is in _site/ - ready to deploy
```

## Customization

- **Theme colors**: Edit `:root` variables in `assets/css/style.css`
- **Site title/description**: Update `_config.yml`
- **Navigation**: Edit `_includes/header.html`
- **Layouts**: Modify `_layouts/default.html` and `_layouts/page.html`
