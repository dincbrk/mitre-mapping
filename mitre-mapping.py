import re
import os
import json
import requests
import argparse
from datetime import datetime, timedelta
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

# URL and local file details
MITRE_ATTACK_URL = "https://github.com/mitre/cti/raw/master/enterprise-attack/enterprise-attack.json"
LOCAL_JSON_FILE = "enterprise-attack.json"
FILE_EXPIRATION_DAYS = 90

# Function to check if the JSON file exists and is older than 30 days
def check_and_download_mitre_data():
    if os.path.exists(LOCAL_JSON_FILE):
        file_creation_time = datetime.fromtimestamp(os.path.getctime(LOCAL_JSON_FILE))
        if datetime.now() - file_creation_time > timedelta(days=FILE_EXPIRATION_DAYS):
            print("MITRE ATT&CK data is older than 30 days. Downloading new data...")
            os.remove(LOCAL_JSON_FILE)
            download_mitre_attack_data()
        else:
            print("MITRE ATT&CK data is up to date.")
    else:
        print("MITRE ATT&CK data not found. Downloading...")
        download_mitre_attack_data()

# Function to download MITRE ATT&CK data with download progress
def download_mitre_attack_data():
    response = requests.get(MITRE_ATTACK_URL, stream=True)
    total_size = int(response.headers.get('content-length', 0)) / 1024  # Convert to KB
    downloaded_size = 0

    with open(LOCAL_JSON_FILE, 'wb') as file:
        for data in response.iter_content(1024):
            downloaded_size += len(data) / 1024  # Convert to KB
            file.write(data)
            print(f"Downloading: {downloaded_size:.2f}KB / {total_size:.2f}KB", end='\r')
    print("\nMITRE ATT&CK data downloaded.")

# Load MITRE ATT&CK data from local JSON file
def load_mitre_data():
    with open(LOCAL_JSON_FILE, 'r') as file:
        mitre_data = json.load(file)
    print("MITRE ATT&CK data loaded from local file.")
    return mitre_data

# Function to map commands to MITRE ATT&CK techniques using regex patterns
def map_command_to_mitre(command, mitre_data):
    command = command.strip()
    techniques = []

    # Expanded regex patterns
    if re.search(r'^\s*cd(\s+.*)?$', command):
        techniques.append("T1083")
    elif re.search(r'^\s*ls(\s+.*)?$', command):
        techniques.append("T1083")
    elif re.search(r'^\s*cat\s+.*$', command):
        if re.search(r'\bpasswd\b', command):
            techniques.extend(["T1005", "T1087"])
        elif re.search(r'\bsudoers\b', command):
            techniques.extend(["T1005", "T1087"])
        else:
            techniques.append("T1005")
    elif re.search(r'^\s*echo\s+.*>\s*\.zsh_history\s*$', command):
        techniques.append("T1070")
    elif re.search(r'^\s*whoami\s*$', command):
        techniques.append("T1078")
    elif re.search(r'^\s*clear\s*$', command):
        return []
    elif re.search(r'^\s*uname(\s+.*)?$', command):
        techniques.append("T1005")
    elif re.search(r'^\s*sudo(\s+.*)?$', command):
        techniques.append("T1078")
    elif re.search(r'^\s*history(\s+.*)?$', command):
        techniques.append("T1059")
    elif re.search(r'^\s*(poweroff|reboot)\s*$', command):
        techniques.append("T1086")
    elif re.search(r'^\s*(wget|curl)\s+.*$', command):
        techniques.append("T1105")
    elif re.search(r'^\s*(netstat|ss)(\s+.*)?$', command):
        techniques.append("T1049")
    elif re.search(r'^\s*(chmod|chown)\s+.*$', command):
        techniques.append("T1070")
    elif re.search(r'^\s*(find|grep)\s+.*$', command):
        techniques.append("T1083")
    elif re.search(r'^\s*systemctl\s+.*$', command):
        techniques.append("T1060")
    elif re.search(r'^\s*(ps|top)(\s+.*)?$', command):
        techniques.append("T1083")
    elif re.search(r'^\s*(traceroute|ping)\s+.*$', command):
        techniques.append("T1069")
    else:
        techniques.append("Unknown")

    technique_info = []
    for technique in techniques:
        info = next(
            (
                item for item in mitre_data['objects']
                if technique in item.get("external_references", [{}])[0].get("external_id", "")
            ),
            {
                "name": "Unknown Technique",
                "description": "No description available.",
                "solutions": ["No solutions available."]
            }
        )

        # If no explicit solutions, fallback to description as a 'mitigation/solution'
        if not info.get('solutions'):
            info['solutions'] = [info.get('description', 'No description available.')]

        technique_info.append(info)

    return technique_info

# Function to analyze bash history
def analyze_bash_history(file_path, mitre_data):
    with open(file_path, 'r') as file:
        lines = file.readlines()

    results = []
    for line in lines:
        commands = line.strip().split(';')
        for command in commands:
            techniques = map_command_to_mitre(command, mitre_data)
            if techniques:
                results.append({
                    "command": command,
                    "techniques": techniques
                })

    return results

# Function to generate a PDF report
def generate_pdf_report(results, output_file):
    doc = SimpleDocTemplate(output_file, pagesize=letter, rightMargin=inch / 2, leftMargin=inch / 2, topMargin=inch, bottomMargin=inch)
    story = []

    styles = getSampleStyleSheet()
    title_style = styles['Title']
    heading_style = styles['Heading2']
    normal_style = styles['Normal']
    bullet_style = ParagraphStyle(name='Bullet', parent=styles['Normal'], leftIndent=20, bulletIndent=10, spaceBefore=5, spaceAfter=5)

    story.append(Paragraph("MITRE ATT&CK Mapping Report", title_style))
    story.append(Spacer(1, 12))

    for result in results:
        story.append(Paragraph(f"Command: {result['command']}", heading_style))
        story.append(Spacer(1, 6))

        for technique in result['techniques']:
            story.append(Paragraph(f"Technique: {technique['name']}", normal_style))
            story.append(Paragraph(f"Description: {technique['description']}", normal_style))
            story.append(Paragraph("Solutions:", normal_style))
            for solution in technique.get('solutions', []):
                story.append(Paragraph(f"  * {solution}", bullet_style))
            story.append(Spacer(1, 12))

    doc.build(story)
    print(f"PDF report generated: {output_file}")

# Function to parse command-line arguments
def parse_arguments():
    parser = argparse.ArgumentParser(description="Analyze bash history and map commands to MITRE ATT&CK techniques.")
    parser.add_argument('-f', '--file', required=True, help="Path to the bash history file")
    parser.add_argument('-o', '--output', help="Output PDF file name (optional)")
    return parser.parse_args()

# Main function
def main():
    args = parse_arguments()

    # Check and download MITRE ATT&CK data if necessary
    check_and_download_mitre_data()

    # Load the MITRE ATT&CK data from the local file
    mitre_data = load_mitre_data()

    # Analyze bash history
    results = analyze_bash_history(args.file, mitre_data)

    # Print the results step-by-step in terminal
    print("Analysis Results:")
    for result in results:
        print(f"Command: {result['command']}")
        for technique in result['techniques']:
            print(f"  Technique: {technique['name']}")
            print(f"  Description: {technique['description']}")
            if technique.get('solutions'):
                print("  Solutions:")
                for solution in technique['solutions']:
                    print(f"    * {solution}")

    # Generate PDF report if output file is specified
    if args.output:
        generate_pdf_report(results, args.output)

if __name__ == "__main__":
    main()
