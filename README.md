# FMC Rule Exporter

A Python script for extracting and exporting Cisco Firepower Management Center (FMC) access control policies (ACPs) and related objects into a CSV file. The script retrieves rules, zones, networks, protocols, and other related information.
## Features

- Extracts access control policies (ACPs) from Cisco FMC.
- Processes and maps network objects, ports, protocols, and URL groups.
- Exports extracted rules to a CSV file with detailed information such as:
  - Rule position and name.
  - Source and destination zones/networks.
  - Protocols and destination ports.
  - Applications and URLs.
  - Actions, IPS policies, comments, and more.

## Prerequisites

1. Python 3.8 or later installed.
2. Access to Cisco FMC API with appropriate credentials.
3. Dependencies listed in `requirements.txt`.

## Installation

Install the required Python packages:
bash
Kód másolása
pip install -r requirements.txt

Provide the following details when prompted:

FMC hostname.
Username and password for FMC API access.
Select an access control policy (ACP) from the list presented.

The script will:

Export relevant FMC objects and rules into JSON files.
Process and organize the data.
Generate a CSV file with the extracted rules in the current directory.
Find the exported rules in the test.csv file (default name) or a dynamically generated file named with the ACP and date.

Example Output
A sample CSV output includes fields like:

Rule Name
Source and Destination Zones
Networks and IPs
Protocols and Ports
Applications and URLs
Actions and Comments


Sample Run

Enter FMC hostname: fmc.example.com
Enter FMC username: admin
Enter FMC password: ****
ACP available in global domain:
    1. Example Policy 1
    2. Example Policy 2
Enter the number corresponding to the Access Control Policy: 1
Process completed in 120.45 seconds.
File Structure
script.py: Main script for extracting and exporting rules.
requirements.txt: Contains the Python dependencies.
Output JSON and CSV files:
network_objects.json, rules.json, etc.
test.csv (or custom-named CSV files).

Dependencies
The following Python libraries are required:

fireREST: Python library for FMC API interactions.
requests: For HTTP requests.
csv: Built-in library for CSV file operations.
json: Built-in library for parsing JSON.

Install dependencies using:
pip install -r requirements.txt

License
This project is licensed under the MIT License. See LICENSE for details.

Contributing
Feel free to fork the repository and submit pull requests. Contributions are welcome!
