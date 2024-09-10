# MITRE ATT&CK Bash Command Analysis Tool

This project is a Python application that analyzes Bash command history and maps those commands to MITRE ATT&CK framework techniques. It helps classify Bash commands based on possible attack techniques for cybersecurity analysis.

## Features
- Maps Bash commands to MITRE ATT&CK techniques
- Downloads and updates MITRE ATT&CK data in JSON format
- Generates a PDF report with analysis results
- Displays download progress and real-time analysis steps in the terminal

## Requirements
- Python 3
- Required Python libraries (`requests`, `reportlab`)

## Installation
1. Install the required dependencies:
   ```bash
   pip install -r requirements.txt

## Usage
   ```bash
   python mitre-mapping.py --file bash_history_file_path --output output_file_name

## Example

   ```bash
   python3 mitre-mapping.py -f .zsh_history -o report
   python3 mitre-mapping.py --file .zsh_history --output report
