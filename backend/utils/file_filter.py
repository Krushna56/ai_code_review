"""
File filtering utilities for code analysis.

This module provides functions to filter out non-code files during analysis,
such as documentation files, readme files, JSON files, and other configuration files.
"""

import os
from pathlib import Path
from typing import Union
import fnmatch
import config


def should_ignore_file(file_path: Union[str, Path]) -> bool:
    """
    Check if a file should be ignored during analysis.
    
    Args:
        file_path: Path to the file to check
        
    Returns:
        True if the file should be ignored, False otherwise
    """
    file_path = Path(file_path)
    filename = file_path.name.lower()
    
    # Check against ignored file patterns (case-insensitive)
    for pattern in config.IGNORED_FILE_PATTERNS:
        if fnmatch.fnmatch(filename, pattern.lower()):
            return True
    
    # Check against ignored extensions
    file_ext = file_path.suffix.lower()
    if file_ext in config.IGNORED_EXTENSIONS:
        return True
    
    return False


def should_ignore_directory(dir_path: Union[str, Path]) -> bool:
    """
    Check if a directory should be skipped during analysis.
    
    Args:
        dir_path: Path to the directory to check
        
    Returns:
        True if the directory should be ignored, False otherwise
    """
    dir_path = Path(dir_path)
    dir_name = dir_path.name.lower()
    
    # Check against ignored directory patterns
    for pattern in config.IGNORED_DIRECTORIES:
        # Handle wildcard patterns
        if '*' in pattern:
            if fnmatch.fnmatch(dir_name, pattern.lower()):
                return True
        else:
            if dir_name == pattern.lower():
                return True
    
    return False


def is_code_file(file_path: Union[str, Path]) -> bool:
    """
    Determine if a file is a code file worth analyzing.
    
    Args:
        file_path: Path to the file to check
        
    Returns:
        True if the file is a code file, False otherwise
    """
    file_path = Path(file_path)
    
    # First check if it should be ignored
    if should_ignore_file(file_path):
        return False
    
    # Check if it has a supported extension
    file_ext = file_path.suffix.lower()
    if file_ext in config.SUPPORTED_EXTENSIONS:
        return True
    
    # For secret detection, we want to check some additional file types
    # but only if they're not in the ignored list
    code_extensions = ['.py', '.java', '.js', '.go', '.rb', '.php', '.c', '.cpp', 
                      '.cs', '.swift', '.kt', '.rs', '.scala', '.ts', '.jsx', '.tsx']
    
    return file_ext in code_extensions


def get_filtered_files(root_path: Union[str, Path], extensions: list = None) -> list:
    """
    Get a list of files from a directory, filtered by the ignore rules.
    
    Args:
        root_path: Root directory to search
        extensions: Optional list of extensions to filter by (e.g., ['.py', '.js'])
                   If None, uses SUPPORTED_EXTENSIONS from config
        
    Returns:
        List of file paths that pass the filter
    """
    root_path = Path(root_path)
    filtered_files = []
    
    if extensions is None:
        extensions = config.SUPPORTED_EXTENSIONS
    
    for root, dirs, files in os.walk(root_path):
        # Filter out ignored directories (modify in-place to prevent os.walk from entering them)
        dirs[:] = [d for d in dirs if not should_ignore_directory(Path(root) / d)]
        
        for file in files:
            file_path = Path(root) / file
            
            # Skip ignored files
            if should_ignore_file(file_path):
                continue
            
            # Check extension if specified
            if extensions and file_path.suffix.lower() not in extensions:
                continue
            
            filtered_files.append(file_path)
    
    return filtered_files


def filter_file_tree(items: list, base_path: Union[str, Path]) -> list:
    """
    Filter a list of file/directory names based on ignore rules.
    
    Args:
        items: List of file/directory names
        base_path: Base path for the items
        
    Returns:
        Filtered list of items
    """
    base_path = Path(base_path)
    filtered = []
    
    for item in items:
        item_path = base_path / item
        
        # Check if it's a directory
        if item_path.is_dir():
            if not should_ignore_directory(item_path):
                filtered.append(item)
        else:
            # It's a file
            if not should_ignore_file(item_path):
                filtered.append(item)
    
    return filtered
