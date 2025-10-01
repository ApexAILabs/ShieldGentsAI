# 🎨 ShieldGents Logo Usage Guide

## Logo Locations

### Where the Logo is Displayed

1. **GitHub README** (`README.md`)
   - Main ASCII logo at top of page
   - Visible to all visitors
   - Auto-rendered by GitHub

2. **Welcome Script** (`examples/welcome.py`)
   ```bash
   uv run python examples/welcome.py
   ```
   - Shows colorful banner
   - Includes quick start info

3. **CLI Tool** (`src/shieldgents/interface/cli.py`)
   ```bash
   uv run shieldgents version
   ```
   - Shows logo in terminal
   - Part of command-line interface

4. **Logo Reference** (`docs/logo.txt`)
   - All logo variations
   - For developers and documentation

## Using the Logo

### In Python Code

```python
from shieldgents.assets import print_logo
from shieldgents.interface import print_banner

# Simple logo
print_logo()

# Full banner with version info
print_banner()
```

### In Your Own Scripts

```python
LOGO = """
   _____ __    _      __    ________            __
  / ___// /_  (_)__  / /___/ / ____/__  ____  / /______
  \__ \/ __ \/ / _ \/ / __  / / __/ _ \/ __ \/ __/ ___/
 ___/ / / / / /  __/ / /_/ / /_/ /  __/ / / / /_(__  )
/____/_/ /_/_/\___/_/\__,_/\____/\___/_/ /_/\__/____/

          🛡️  Security for AI Agents  🛡️
"""

print(LOGO)
```

### In Documentation

Use the badge/minimal versions from `docs/logo.txt`:

```
╔═══════════════════╗
║  🛡️  ShieldGents ║
╚═══════════════════╝
```

### In Presentations

Use the banner format:
```
████████████████████████████████████████████
█░░  🛡️  SHIELDGENTS  🛡️                ░░█
█░░  Security Tooling for AI Agents      ░░█
████████████████████████████████████████████
```

## Logo Variations

See `docs/logo.txt` for:
- ASCII art variations
- Badge styles
- Icon options (🛡️, 🔒, 🔐)
- Color schemes
- Taglines

## When to Show Logo

### ✅ Show Logo When:
- First-time package import or installation
- Running welcome/setup scripts
- CLI help commands
- Version display
- Documentation headers

### ❌ Don't Show Logo:
- Background processes (set `SHIELDGENTS_SUPPRESS_LOGO=1`)
- Automated scripts that require silent output
- When quiet mode is explicitly enabled by users

## Customization

### Colors (in terminal)

```python
# Cyan
print("\033[1;36m" + LOGO + "\033[0m")

# Green
print("\033[1;32m" + LOGO + "\033[0m")

# Blue
print("\033[1;34m" + LOGO + "\033[0m")
```

### Size Variations

**Minimal:**
```
🛡️ ShieldGents
```

**Small:**
```
┌─────────────────────────────────┐
│   🛡️  S H I E L D G E N T S    │
└─────────────────────────────────┘
```

**Full ASCII:**
(See README.md or docs/logo.txt)

## Branding Guidelines

### Colors
- Primary: #2E86AB (Blue)
- Secondary: #A23B72 (Purple)
- Accent: #F18F01 (Orange)

### Typography
- Logo: Monospace/Fixed-width font
- Tagline: Sans-serif
- Body text: System default

### Spacing
- Always include blank line before/after logo
- Center-align for best appearance

## Examples

### Startup Banner
```python
print("\n" + LOGO + "\n")
print("Welcome to ShieldGents!")
print("Type 'help' for commands\n")
```

### CLI Header
```python
def show_header():
    print_banner()
    print("ShieldGents CLI v0.1.0")
    print("=" * 70)
```

### Error Messages
```python
print("🛡️ ShieldGents Error:")
print("Something went wrong...")
```

Use the shield emoji 🛡️ as a prefix for brand consistency!
