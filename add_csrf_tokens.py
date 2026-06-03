#!/usr/bin/env python3
"""
Script to add CSRF tokens to all forms in templates that don't already have them.
This is a one-time migration script for security hardening.
"""
import os
import re
from pathlib import Path

TEMPLATES_DIR = Path("templates")
CSRF_TOKEN = '<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">'

def has_csrf_token(content):
    """Check if the form already has a CSRF token"""
    return 'csrf_token' in content

def add_csrf_to_forms(content):
    """Add CSRF token to all forms that don't have one"""
    if has_csrf_token(content):
        return content, False

    # Pattern to match <form> tags with method="post" (case insensitive)
    # Matches: <form method='post'> or <form method="post">
    pattern = r'(<form[^>]*method=["\']post["\'][^>]*>)'

    def add_token(match):
        form_tag = match.group(1)
        # Add CSRF token right after the form opening tag with a newline
        return f"{form_tag}\n{CSRF_TOKEN}"

    new_content = re.sub(pattern, add_token, content, flags=re.IGNORECASE)

    # Check if any changes were made
    changed = new_content != content
    return new_content, changed

def process_template_file(file_path):
    """Process a single template file"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        new_content, changed = add_csrf_to_forms(content)

        if changed:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(new_content)
            print(f"✓ Updated: {file_path}")
            return True
        else:
            print(f"  Skipped: {file_path} (already has CSRF or no POST forms)")
            return False
    except Exception as e:
        print(f"✗ Error processing {file_path}: {e}")
        return False

def main():
    """Main function to process all template files"""
    if not TEMPLATES_DIR.exists():
        print(f"Error: {TEMPLATES_DIR} directory not found!")
        return

    print("Adding CSRF tokens to all forms in templates...")
    print("=" * 60)

    updated_count = 0
    total_files = 0

    for html_file in TEMPLATES_DIR.rglob("*.html"):
        total_files += 1
        if process_template_file(html_file):
            updated_count += 1

    print("=" * 60)
    print(f"\nSummary:")
    print(f"  Total files processed: {total_files}")
    print(f"  Files updated: {updated_count}")
    print(f"  Files skipped: {total_files - updated_count}")

    if updated_count > 0:
        print("\n⚠️  IMPORTANT: Review the changes and test your forms!")
        print("    Some forms may need manual adjustment.")

if __name__ == "__main__":
    main()
