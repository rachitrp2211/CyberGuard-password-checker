# CyberGuard — GUI Password Analyzer & Reporter

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

**CyberGuard** is a Python-based GUI tool for cybersecurity enthusiasts and professionals. It analyzes password strength, estimates entropy, checks for breaches using the Have I Been Pwned API, generates strong passwords, and creates detailed reports. Ideal for portfolio projects, internships, and demonstrating practical security skills.

---

## Features

- **Password Strength Analysis**: Calculates entropy and strength level (Very Weak → Very Strong)  
- **Breach Detection**: Checks if a password has been exposed using the HIBP API  
- **Password Generator**: Generate strong passwords with configurable length (6–32 characters)  
- **Show/Hide Password**: Toggle password visibility for convenience  
- **Clipboard Support**: Copy and paste passwords easily  
- **Detailed Suggestions**: Provides actionable advice to strengthen passwords  
- **Report Generation**:  
  - Generates `.txt` and `.csv` reports in `reports/` folder  
  - Includes timestamp, entropy, strength, breach result, and input method  

---

## Screenshots

*(Add screenshots in the `screenshots/` folder)*

### Main GUI
![Main GUI](screenshots/gui_main.png)

### Example Report
![Report Example](screenshots/gui_report.png)

---

## Installation

**Requirements:**

- Python 3.8+  
- Pip packages:

```bash
pip install requests pyperclip
