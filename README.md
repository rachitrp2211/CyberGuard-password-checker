<<<<<<< HEAD
CyberGuard — Password Analyzer & Reporter

🔐 CyberGuard is a modern, GUI-based password analysis tool designed for security enthusiasts and professionals. It checks password strength, estimates entropy, detects potential breaches via the Have I Been Pwned API, and generates detailed reports for auditing purposes. Perfect for portfolio projects or internships in cybersecurity.

Features

Password Strength Analysis: Calculates entropy and strength level (Very Weak → Very Strong).

Breach Detection: Uses k-anonymity with the HIBP API
 to check if your password has been compromised.

Password Generator: Generate strong passwords with configurable length (6–32 characters).

Show/Hide Password: Toggle visibility for convenience.

Clipboard Support: Easily Paste or Copy passwords.

Detailed Suggestions: Actionable advice to strengthen your password (e.g., adding symbols, digits, uppercase).

Report Generation:

Daily .txt and .csv reports in reports/ folder.

Includes timestamp, entropy, strength, breach result, and input method.

Optionally include SHA-1 hashes or full plaintext (with warning).

Modern GUI: Dark-themed, color-coded feedback, and user-friendly interface.

Installation

Requirements:

Python 3.8+

Pip packages:

pip install requests pyperclip


Run the tool:

python password_checker_with_report_plus.py

Usage

Enter or generate a password:

Type directly, paste from clipboard, or generate using the slider and button.

Show Password: Click the checkbox to reveal the password if needed.

Check & Save: Click the “Check & Save” button to analyze password and save report.

View Results:

Entropy and Strength level

Breach status

Suggestions to improve password security

Reports: Saved automatically under reports/:

.txt file for human-readable logs

.csv file for spreadsheet-friendly tracking

Screenshot

(Add screenshot here of your GUI with a generated password and results displayed)

Example Report Entry (TXT)
Timestamp: 2025-10-15T16:40:12
Input method: Generated
Checks performed: Entropy check, HIBP breach check
Masked preview: Ab********YZ
SHA1: 4A7D1ED414474E4033AC29CCB8653D9B
Entropy: 70.12
Strength level: Strong
Breach result: No breaches found

Why This Project Stands Out

Demonstrates practical cybersecurity knowledge: password security, entropy calculation, breach detection.

Shows proficiency in Python GUI development (tkinter + ttk) and API integration.

Includes report generation and file handling, highlighting real-world tool-building skills.

Strong candidate showcase for cybersecurity internships or portfolio demonstrations.

Future Enhancements

Multi-user support with encrypted storage.

More advanced password metrics (e.g., Markov chain or dictionary attacks).

Export reports to PDF with charts/graphs.

Multi-language GUI support.
=======
# CyberGuard-password-checker
CyberGuard is a Python GUI tool that analyzes password strength, estimates entropy, checks for breaches via Have I Been Pwned API, generates strong passwords, and creates detailed reports. Ideal for cybersecurity portfolios, internships, and demonstrating practical security skills.
>>>>>>> cb6c1b56d31e804c1e17acd4a81a72c844d7e09a
