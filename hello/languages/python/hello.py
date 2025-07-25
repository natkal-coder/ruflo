#!/usr/bin/env python3
"""
A simple Hello World program demonstrating Python best practices.

This module provides a basic greeting function and serves as an example
of idiomatic Python code following PEP 8 style guidelines.
"""

from typing import Optional


def greet(name: Optional[str] = None) -> str:
    """
    Generate a greeting message.
    
    Args:
        name: Optional name to personalize the greeting.
              If None, uses a generic greeting.
    
    Returns:
        A greeting string.
    
    Examples:
        >>> greet()
        'Hello, World!'
        >>> greet("Python")
        'Hello, Python!'
    """
    if name is None:
        return "Hello, World!"
    return f"Hello, {name}!"


def main() -> None:
    """Main entry point of the program."""
    # Default greeting
    print(greet())
    
    # Personalized greeting example
    print(greet("Python"))


if __name__ == "__main__":
    main()