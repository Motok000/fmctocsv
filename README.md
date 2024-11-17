# FMC Rule Exporter

A Python script for extracting and exporting Cisco Firepower Management Center (FMC) access control policies (ACPs) and related objects into a CSV file. The script retrieves rules, zones, networks, protocols, and other related information.
Simply double-click the CSV file to open it in Excel for example.

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

pip install -r requirements.txt


Provide the following details when prompted:

- FMC hostname.
- Username and password for FMC API access.
- Select an access control policy (ACP) from the list presented.



## The script will:

1. Export relevant FMC objects and rules into JSON files.
2. Process and organize the data.
3. Generate a CSV file with the extracted rules in the current directory.
4. Find the exported rules in a dynamically generated file named with the ACP and date.

## Example Output
A sample CSV output includes fields like:

- Rule Name
- Source and Destination Zones
- Networks and IPs
- Protocols and Ports
- Applications and URLs
- Actions and Comments


## Sample Run

- Enter FMC hostname: <fmc.example.com or ip address>
- Enter FMC username: your_username
- Enter FMC password: ****
- ACP available in global domain:
    - Example Policy 1
    - Example Policy 2
- Enter the number corresponding to the Access Control Policy: 1
- Process completed in 120.45 seconds.


## Dependencies
The following Python libraries are required:

- fireREST: Python library for FMC API interactions.
- requests: For HTTP requests.
- csv: Built-in library for CSV file operations.
- json: Built-in library for parsing JSON.


## License
This project is licensed under the MIT License.

## Contributing
Feel free to fork the repository and submit pull requests. Contributions are welcome!
