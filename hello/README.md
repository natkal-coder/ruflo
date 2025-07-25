# Multi-Language Hello World Project

A clean, organized project demonstrating "Hello World" implementations in multiple programming languages.

## Project Structure

```
hello/
├── README.md                 # This file
├── STRUCTURE.md             # Detailed structure documentation
├── languages/               # Language-specific implementations
│   ├── python/
│   │   └── hello.py
│   ├── javascript/
│   │   ├── hello.js
│   │   └── package.json
│   └── go/
│       ├── hello.go
│       └── go.mod
├── scripts/                 # Utility scripts
│   └── run-all.sh          # Run all implementations
└── shared/                  # Shared resources
    └── templates/          # Common templates
        └── LANGUAGE_README_TEMPLATE.md

```

## Quick Start

### Run All Implementations
```bash
./scripts/run-all.sh
```

### Run Individual Languages

**Python:**
```bash
python languages/python/hello.py
```

**JavaScript:**
```bash
node languages/javascript/hello.js
```

**Go:**
```bash
go run languages/go/hello.go
```

## Language Implementations

Each language implementation follows its respective best practices and conventions:

- **Python**: Uses type hints, docstrings, and follows PEP 8
- **JavaScript**: ES6+ modules, JSDoc comments, async/await patterns
- **Go**: Standard package structure, proper documentation

## Adding New Languages

1. Create a new directory under `languages/`
2. Implement the hello world program following the language's conventions
3. Add a README.md for the language (use the template in `shared/templates/`)
4. Update the `scripts/run-all.sh` script to include the new language
5. Update this README with the new language information

## Contributing

Each language implementation should:
- Follow the language's standard conventions and best practices
- Include proper documentation/comments
- Be self-contained within its directory
- Include any necessary configuration files (package.json, go.mod, etc.)