#!/usr/bin/env python3
"""
Unit tests for the hello module.

This module contains test cases for the greet function
using Python's built-in unittest framework.
"""

import unittest
from hello import greet


class TestGreetFunction(unittest.TestCase):
    """Test cases for the greet function."""
    
    def test_greet_without_name(self):
        """Test greeting without providing a name."""
        self.assertEqual(greet(), "Hello, World!")
    
    def test_greet_with_name(self):
        """Test greeting with a specific name."""
        self.assertEqual(greet("Python"), "Hello, Python!")
        self.assertEqual(greet("Developer"), "Hello, Developer!")
    
    def test_greet_with_empty_string(self):
        """Test greeting with an empty string."""
        self.assertEqual(greet(""), "Hello, !")
    
    def test_greet_with_none(self):
        """Test greeting with None explicitly passed."""
        self.assertEqual(greet(None), "Hello, World!")


if __name__ == "__main__":
    unittest.main()