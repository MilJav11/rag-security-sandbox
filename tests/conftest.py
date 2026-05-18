import subprocess

def pytest_sessionfinish(session, exitstatus):
    """This hook runs automatically at the very end of all Pytest tests."""
    print("\n[+] Pytest completed. Generating Executive Risk Report...")
    subprocess.run(["python", "scripts/generate_report.py"])