from config import get_temp_raw_path
import os

def test_sanitation():
    # Test cases: (input_name, expected_substring)
    test_cases = [
        ("malware:test", "malware_test"),
        ("proc/with/slashes", "proc_with_slashes"),
        ("proc\\with\\backslashes", "proc_with_backslashes"),
        ("proc*with*stars", "proc_with_stars"),
        ("proc?with?questions", "proc_with_questions"),
        ("proc<with>brackets", "proc_with_brackets"),
        ("proc|with|pipes", "proc_with_pipes")
    ]
    
    all_passed = True
    for input_name, expected in test_cases:
        path = get_temp_raw_path(input_name, 1234)
        filename = path.name
        if expected in filename:
            print(f"[PASS] {input_name} -> {filename}")
        else:
            print(f"[FAIL] {input_name} -> {filename} (Expected {expected})")
            all_passed = False
            
    return all_passed

if __name__ == "__main__":
    if test_sanitation():
        print("\n[SUCCESS] Filename sanitation verified.")
    else:
        print("\n[FAILURE] Filename sanitation failed.")
        exit(1)
