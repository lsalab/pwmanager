"""
Tests for main application entry point and integration tests.

This module contains integration tests that test the application
as a whole, including CLI functionality.
"""

import pytest
from pwmanager.datastore import validate_store_path


class TestValidateStorePath:
    """Test validate_store_path function"""
    
    def test_valid_paths(self):
        """Test valid store paths"""
        assert validate_store_path('./data/store.pws') is True
        assert validate_store_path('store.pws') is True
        assert validate_store_path('test/store.pws') is True
    
    def test_invalid_paths(self):
        """Test invalid store paths"""
        assert validate_store_path('') is False
        assert validate_store_path('../store.pws') is False
        assert validate_store_path('/etc/passwd') is False
        assert validate_store_path('/proc/store.pws') is False
        assert validate_store_path('/sys/store.pws') is False
        assert validate_store_path('/dev/store.pws') is False
        assert validate_store_path('/absolute/path.pws') is False
    
    def test_dangerous_patterns(self):
        """Test detection of dangerous patterns"""
        assert validate_store_path('test/../store.pws') is False
        assert validate_store_path('/etc/store.pws') is False
        assert validate_store_path('/proc/store.pws') is False
