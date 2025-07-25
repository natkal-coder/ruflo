# Project Structure Documentation

## Overview

This project follows a clean, modular structure designed for:
- Easy navigation and understanding
- Scalability (easy to add new languages)
- Separation of concerns
- Consistent organization across languages

## Directory Layout

### `/languages/`
Contains all language-specific implementations. Each language has its own subdirectory with:
- The main implementation file
- Language-specific configuration files (package.json, go.mod, etc.)
- Language-specific documentation (if needed)
- Test files (if applicable)

**Naming Convention:**
- Directory names: lowercase language name (e.g., `python`, `javascript`, `go`)
- Main files: `hello.<extension>` (e.g., `hello.py`, `hello.js`, `hello.go`)

### `/scripts/`
Contains utility scripts for project management:
- `run-all.sh` - Executes all language implementations in sequence
- Future scripts for testing, benchmarking, etc.

### `/shared/`
Contains resources shared across all implementations:
- `/templates/` - Common templates for documentation, new language setup, etc.
- Future shared resources like common test data, benchmarks, etc.

## Design Principles

1. **Self-Contained Languages**: Each language directory should be independently runnable
2. **Consistent Naming**: Follow the same naming patterns across all languages
3. **Best Practices**: Each implementation follows its language's conventions
4. **Documentation**: Every language should have clear instructions for running
5. **Automation**: Scripts should handle common tasks like running all implementations

## Adding a New Language

To add a new language implementation:

1. Create directory: `mkdir -p languages/<language_name>`
2. Implement `hello.<extension>` following the language's conventions
3. Add any necessary configuration files
4. Create a README.md for the language (use shared template)
5. Update `/scripts/run-all.sh` to include the new language
6. Update the main README.md

## File Organization Guidelines

### Language Directories
```
languages/<language>/
├── hello.<ext>              # Main implementation
├── README.md               # Language-specific documentation
├── <config_files>          # package.json, go.mod, requirements.txt, etc.
├── test_hello.<ext>        # Test file (if applicable)
└── examples/               # Additional examples (optional)
```

### Shared Resources
```
shared/
├── templates/
│   ├── LANGUAGE_README_TEMPLATE.md
│   └── NEW_LANGUAGE_CHECKLIST.md
├── benchmarks/             # Common benchmark suite (future)
└── docs/                   # Shared documentation (future)
```

## Benefits of This Structure

1. **Scalability**: Easy to add new languages without affecting existing ones
2. **Maintainability**: Clear separation makes updates easier
3. **Discoverability**: Intuitive structure helps new contributors
4. **Consistency**: Uniform organization across all languages
5. **Automation-Friendly**: Scripts can easily iterate over language directories