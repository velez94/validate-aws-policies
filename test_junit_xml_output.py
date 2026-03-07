#!/usr/bin/env python3
"""
Test script to verify JUnit XML output is AWS CodeBuild compatible.
"""

import xml.etree.ElementTree as ET
from pathlib import Path
import sys

def validate_junit_xml(xml_file: Path) -> bool:
    """Validate JUnit XML file meets AWS CodeBuild requirements."""
    
    print(f"Validating {xml_file}...")
    
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        
        # Check root element
        if root.tag != "testsuites":
            print("✗ Root element must be 'testsuites'")
            return False
        print("✓ Root element is 'testsuites'")
        
        # Check required attributes on testsuites
        required_attrs = ["name", "tests", "failures", "errors", "skipped", "time"]
        for attr in required_attrs:
            if attr not in root.attrib:
                print(f"✗ Missing required attribute '{attr}' on testsuites")
                return False
        print(f"✓ All required attributes present on testsuites: {', '.join(required_attrs)}")
        
        # Check timestamp format (should be ISO 8601 without microseconds)
        timestamp = root.get("timestamp", "")
        if "T" not in timestamp or "." in timestamp:
            print(f"✗ Timestamp format incorrect: {timestamp} (should be YYYY-MM-DDTHH:MM:SS)")
            return False
        print(f"✓ Timestamp format correct: {timestamp}")
        
        # Check each testsuite
        testsuites = root.findall("testsuite")
        if not testsuites:
            print("✗ No testsuite elements found")
            return False
        print(f"✓ Found {len(testsuites)} testsuite(s)")
        
        for idx, testsuite in enumerate(testsuites, 1):
            suite_name = testsuite.get("name", f"suite_{idx}")
            
            # Check required attributes on testsuite
            required_suite_attrs = ["name", "tests", "failures", "errors", "skipped", "time", "timestamp"]
            for attr in required_suite_attrs:
                if attr not in testsuite.attrib:
                    print(f"✗ Missing required attribute '{attr}' on testsuite '{suite_name}'")
                    return False
            
            # Check for system-out and system-err
            system_out = testsuite.find("system-out")
            system_err = testsuite.find("system-err")
            
            if system_out is None:
                print(f"✗ Missing <system-out> element in testsuite '{suite_name}'")
                return False
            
            if system_err is None:
                print(f"✗ Missing <system-err> element in testsuite '{suite_name}'")
                return False
            
            print(f"✓ Testsuite '{suite_name}' has all required attributes and elements")
            
            # Check testcases
            testcases = testsuite.findall("testcase")
            if not testcases:
                print(f"✗ No testcase elements in testsuite '{suite_name}'")
                return False
            
            for testcase in testcases:
                if "classname" not in testcase.attrib or "name" not in testcase.attrib:
                    print(f"✗ Testcase missing required attributes in '{suite_name}'")
                    return False
        
        print("\n✓ XML is AWS CodeBuild compatible!")
        return True
        
    except ET.ParseError as e:
        print(f"✗ XML parsing error: {e}")
        return False
    except Exception as e:
        print(f"✗ Validation error: {e}")
        return False


def check_xml_declaration(xml_file: Path) -> bool:
    """Check that XML declaration is clean."""
    with open(xml_file, 'r', encoding='utf-8') as f:
        first_line = f.readline()
        
    if not first_line.startswith('<?xml version="1.0" encoding="UTF-8"?>'):
        print(f"✗ XML declaration incorrect: {first_line.strip()}")
        return False
    
    print("✓ XML declaration is clean")
    return True


if __name__ == "__main__":
    # This script can be used to validate any JUnit XML file
    # For now, just print instructions
    print("JUnit XML Validation Script")
    print("=" * 50)
    print("\nThis script validates JUnit XML files for AWS CodeBuild compatibility.")
    print("\nTo test:")
    print("1. Run your policy validation with --format xml")
    print("2. Run: python3 test_junit_xml_output.py <xml_file>")
    print("\nRequired elements:")
    print("  - testsuites: name, tests, failures, errors, skipped, time, timestamp")
    print("  - testsuite: name, tests, failures, errors, skipped, time, timestamp")
    print("  - testsuite must contain: <system-out> and <system-err>")
    print("  - testcase: classname, name, time")
    print("  - Timestamp format: YYYY-MM-DDTHH:MM:SS (no microseconds)")
    
    if len(sys.argv) > 1:
        xml_file = Path(sys.argv[1])
        if xml_file.exists():
            print(f"\nValidating {xml_file}...\n")
            is_valid_declaration = check_xml_declaration(xml_file)
            is_valid_structure = validate_junit_xml(xml_file)
            
            if is_valid_declaration and is_valid_structure:
                print("\n✓ All checks passed!")
                sys.exit(0)
            else:
                print("\n✗ Validation failed")
                sys.exit(1)
        else:
            print(f"\n✗ File not found: {xml_file}")
            sys.exit(1)
