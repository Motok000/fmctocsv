import json
import csv
import datetime
import getpass
from fireREST import FMC
import requests
import time

# Dictionary mapping protocol numbers to protocol names.
# Key: Protocol number (as string)
# Value: Protocol name
protocol_names = {
    "1": "ICMP",   # Internet Control Message Protocol
    "6": "TCP",    # Transmission Control Protocol
    "17": "UDP",   # User Datagram Protocol
    "47": "GRE",   # Generic Routing Encapsulation
    "50": "ESP",   # Encapsulating Security Payload
    "51": "AH",    # Authentication Header
    "88": "EIGRP", # Enhanced Interior Gateway Routing Protocol
    "89": "OSPF",  # Open Shortest Path First
    "112": "VRRP", # Virtual Router Redundancy Protocol
    "113": "PGM",  # Pragmatic General Multicast
    "115": "L2TP", # Layer 2 Tunneling Protocol
    "118": "STP",  # Spanning Tree Protocol
    "124": "LDP",  # Label Distribution Protocol
    "132": "SCTP", # Stream Control Transmission Protocol
    "143": "IPX",  # Internetwork Packet Exchange
    "144": "RIP",  # Routing Information Protocol
    # Add more protocol numbers and names as needed
}

# Function to load JSON files into a list of dictionaries
def load_json_files(file_paths):
    """
    Load multiple JSON files and return their contents as a list of dictionaries.

    Parameters:
        file_paths (list): A list of file paths to the JSON files.

    Returns:
        list: A list of dictionaries containing the contents of the JSON files.
    """
    data_list = []
    for file_path in file_paths:
        with open(file_path, 'r') as file:
            data = json.load(file)
            data_list.append(data)
    return data_list

# Function to write extracted rules to a CSV file
def write_to_csv(extracted_rules, filename):
    """Write extracted rules to a CSV file."""
    # Define the field names for the CSV file
    fieldnames = ['Rule Position', 'Rule Name', 'Source Zones','Destination Zones', 'Source Networks', 'Source Networks IPs' , 'Destination Networks', 'Destination Networks IPs', 'Protocol', 'Destination Ports', 'Url', 'App', 'Action', 'Enabled', 'IPS Policy', 'Comment']

    # Open the CSV file in write mode
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        # Create a CSV writer object
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames, delimiter=';')

        # Write the header row
        writer.writeheader()

        # Write each extracted rule as a row in the CSV file
        for rule in extracted_rules:
            writer.writerow({
                'Rule Position': rule['pos'],
                'Rule Name': rule['name'],
                'Source Zones': '\n'.join(rule['sZones']),
                'Destination Zones': '\n'.join(rule['dZones']),
                'Source Networks': '\n'.join(rule['sNetwork']),
                'Source Networks IPs': '\n'.join(rule['sNetworkIP']),
                'Destination Networks': '\n'.join(rule['dNetwork']),
                'Destination Networks IPs': '\n'.join(rule['dNetworkIP']),
                'Protocol': '\n'.join(rule['proto']),
                'Destination Ports': '\n'.join(rule['dPort']),
                'Url': '\n'.join(rule['url']),
                'App': '\n'.join(rule['app']),
                'Action': rule['action'],
                'Enabled': rule['enable'],
                'IPS Policy': rule['ips'],
                'Comment': '\n'.join(rule['comment'])
            })

# Function to process network objects from a list of dictionaries
def process_network_objects(data_list):
    """
    Process network objects from a list of dictionaries.

    Parameters:
        data_list (list): List of dictionaries containing JSON data.

    Returns:
        dict: A dictionary containing processed network objects.
    """
    network_group_objects_ip_hashmap = {}

    for data in data_list:
        for temp in data:
            if temp['type'] == 'Host' or temp['type'] == 'Network' or temp['type'] == 'FQDN':
                network_group_objects_ip_hashmap[temp['name']] = temp['value']
            elif temp['type'] == 'NetworkGroup':
                network_group_objects_ip_hashmap[temp['name']] = []
                for local in temp.get('objects', []):
                    network_group_objects_ip_hashmap[temp['name']].append(local['name'])
                for local in temp.get('literals', []):
                    network_group_objects_ip_hashmap[temp['name']].append(local['value'])
            elif temp['type'] == 'Range':
                network_group_objects_ip_hashmap[temp['name']] = temp['value']
            elif temp['type'] == 'ProtocolPortObject':
                try:
                    network_group_objects_ip_hashmap[temp['name']] = [temp['protocol'], temp['port']]
                except:
                    network_group_objects_ip_hashmap[temp['name']] = ['Error, no port key (no port)']
            elif temp['type'] == "ICMPV4Object":
                network_group_objects_ip_hashmap[temp['name']] = ['icmp', temp['name']]
            elif temp['type'] == 'PortObjectGroup':
                network_group_objects_ip_hashmap[temp['name']] = []
                for local in temp.get('objects', []):
                    network_group_objects_ip_hashmap[temp['name']].append(local['name'])
                for local in temp.get('literals', []):
                    network_group_objects_ip_hashmap[temp['name']].append(local['value'])
            elif temp['type'] == 'Url':
                network_group_objects_ip_hashmap[temp['name']] = temp['url']
            elif temp['type'] == 'UrlGroup':
                network_group_objects_ip_hashmap[temp['name']] = []
                for local in temp.get('objects', []):
                    network_group_objects_ip_hashmap[temp['name']].append(local['name'])
                for local in temp.get('literals', []):
                    network_group_objects_ip_hashmap[temp['name']].append(local['value'])

    return network_group_objects_ip_hashmap

def merge_objects(network_group_objects_ip_hashmaps):
    """
    Merge network group objects dictionaries.

    Parameters:
        network_group_objects_ip_hashmaps (list): List of dictionaries containing network group objects.

    Returns:
        dict: A merged dictionary containing all network group objects.
    """
    last_counter = 0
    while True:
        counter = 0       
        for key, value in network_group_objects_ip_hashmap.items():
            if isinstance(value, list):
                for ind, values in enumerate(value):
                    try:
                        if network_group_objects_ip_hashmap[values][1] != values:
                            try:
                                if isinstance(network_group_objects_ip_hashmap[values], list):
                                    network_group_objects_ip_hashmap[key][ind:ind+1] = network_group_objects_ip_hashmap[values]
                                    counter += 1
                                else:
                                    network_group_objects_ip_hashmap[key][ind] = network_group_objects_ip_hashmap[values]
                                    counter += 1
                            except:
                                continue
                    except:
                        continue
            else:
                try:
                    network_group_objects_ip_hashmap[key] = network_group_objects_ip_hashmap[value]
                    counter += 1
                except:
                    continue

        if  counter == last_counter:
            break
        else: last_counter = counter



def extract_mandatory_fields(rule):
    """Extract mandatory fields from a rule dictionary."""
    # Initialize mandatory fields with default values
    ips = rule.get('ipsPolicy', {}).get('name', 'NULL')
    file = rule.get('filePolicy', {}).get('name', 'NULL')
    variable = rule.get('variableSet', {}).get('name', 'NULL')
    fmcEvents = rule.get('sendEventsToFMC', 'NULL')
    begin = rule.get('logBegin', 'NULL')
    end = rule.get('logEnd', 'NULL')
    syslog = rule.get('enableSyslog', 'NULL')
    enable = rule['enabled']
    action = rule['action']

    return ips, file, variable, fmcEvents, begin, end, syslog, enable, action

def process_rules(data_list):
    """Process rules data and extract relevant information."""
    extracted_data = []  # Initialize an empty list to store extracted data
    pos = 1  # Position of the rule
    for rule in data_list[9]:
        # Extract mandatory fields
        ips, file, variable, fmcEvents, begin, end, syslog, enable, action = extract_mandatory_fields(rule)

        # Extract source and destination zones
        sZones = []
        dZones = []
        for zone_list in rule.get('sourceZones', {}).values():
            for zone in zone_list:
                sZones.append(zone['name'])
        if not sZones:
            sZones = ["Any"]

        for zone_list in rule.get('destinationZones', {}).values():
            for zone in zone_list:
                dZones.append(zone['name'])
        if not dZones:
            dZones = ["Any"]


        # Extract source and destination networks
        sNetwork = []
        sNetworkIP = []
        dNetwork = []
        dNetworkIP = []
        for key, value in rule.get('sourceNetworks', {}).items():
            for network in value:
                if 'literals' in key:
                    sNetwork.append(network['value'])
                    sNetworkIP.append(network['value'])
                    #if isinstance(network_group_objects_ip_hashmap[network['value']], list):
                    #    sNetworkIP.extend(network_group_objects_ip_hashmap[network['value']])
                    #else:
                    #    sNetworkIP.append(network_group_objects_ip_hashmap[network['value']])
                if 'objects' in key:
                    sNetwork.append(network['name'])
                    if network['type'] == 'Country' or network['type'] == 'Geolocation':
                        sNetworkIP.append(network['type'])
                    elif isinstance(network_group_objects_ip_hashmap[network['name']], list):
                        sNetworkIP.extend(network_group_objects_ip_hashmap[network['name']])
                    else:
                        sNetworkIP.append(network_group_objects_ip_hashmap[network['name']])
        if not sNetwork:
            sNetwork = ["Any"]
            sNetworkIP = ["Any"]

        for key, value in rule.get('destinationNetworks', {}).items():
            for network in value:
                if 'literals' in key:
                    dNetwork.append(network['value'])
                    dNetworkIP.append(network['value'])
                    #if isinstance(network_group_objects_ip_hashmap[network['value']], list):
                    #    dNetworkIP.extend(network_group_objects_ip_hashmap[network['value']])
                    #else:
                    #    dNetworkIP.append(network_group_objects_ip_hashmap[network['value']])
                if 'objects' in key:
                    dNetwork.append(network['name'])
                    if network['type'] == 'Country' or network['type'] == 'Geolocation':
                        dNetworkIP.append(network['type'])
                    elif isinstance(network_group_objects_ip_hashmap[network['name']], list):
                        dNetworkIP.extend(network_group_objects_ip_hashmap[network['name']])
                    else:
                        dNetworkIP.append(network_group_objects_ip_hashmap[network['name']])
        if not dNetwork:
            dNetwork = ["Any"]
            dNetworkIP = ["Any"]

        # Extract protocol and destination ports
        proto = []
        dPort = []
        for key, value in rule.get('destinationPorts', {}).items():
            for port in value:
                if 'literals' in key: 
                    protocol_number = port['protocol']
                    protocol_name = protocol_names.get(protocol_number, f"Unknown ({protocol_number})")                        
                    proto.append(protocol_name)
                    if 'port' in port:
                        dPort.append(port['port'])
                    else:
                        dPort.append(" ")
                if 'objects' in key:
                    proto.extend(network_group_objects_ip_hashmap[port['name']][0::2])
                    dPort.extend(network_group_objects_ip_hashmap[port['name']][1::2])
        if not dPort:
            dPort = ['Any']
        if not proto:
            proto = ['Any']

        # Extract applications and URLs
        app = []
        url = []
        for key, value in rule.get('applications', {}).items():
            for app_entry in value:
                app.append(app_entry['name'])
        if not app:
            app = ["Any"]
        for key, value in rule.get('urls', {}).items():
            for url_entry in value:
                if "urlCategoriesWithReputation" in key:
                    if 'name' not in url_entry.get('category', {}):
                        url.append('Uncategorized')
                    else:
                        url.append(url_entry['category']['name'])
                elif "literals" in key:
                    url.append(url_entry['url'])
                else:
                    if isinstance(network_group_objects_ip_hashmap[url_entry['name']], list):
                        url.extend(network_group_objects_ip_hashmap[url_entry['name']])
                    else:
                        url.append(network_group_objects_ip_hashmap[url_entry['name']])

        if not url:
            url = ["Any"]

        # Extract VLAN tags
        vlan = []
        for key, value in rule.get('vlanTags', {}).items():
            for vlan_entry in value:
                if 'VlanTagLiteral' in vlan_entry['type']:
                    vlan.append(vlan_entry['startTag'])
                else:
                    vlan.append(vlan_entry['name'])
        if not vlan:
            vlan = ["Any"]

        # Extract comment history
        comment = []
        for entry in rule.get('commentHistoryList', []):
            comment.append(entry.get('comment', 'Not Applicable'))
        if not comment:
            comment = ["Not Applicable"]

        # Store extracted data as a dictionary
        rule_data = {
            'pos': pos,
            'name': rule['name'],
            'sZones': sZones,
            'dZones': dZones,
            'sNetwork': sNetwork,
            'sNetworkIP': sNetworkIP,
            'dNetwork': dNetwork,
            'dNetworkIP': dNetworkIP,
            'proto': proto,
            'dPort': dPort,
            'url': url,
            'app': app,
            'action': action,
            'enable': enable,
            'ips': ips,
            'comment': comment
        }

        extracted_data.append(rule_data)  # Append the extracted data for this rule to the list
        pos += 1  # Increment the position

    return extracted_data  # Return the list of extracted data


def generate_filename(custom_name=None):
    now = datetime.datetime.now()
    if custom_name:
        return f"{custom_name}_{now.strftime('%Y_%m_%d')}.csv"
    else:
        return f"extracted_rules_{now.strftime('%Y_%m_%d')}.csv"

def get_acp_selection(fmc):
    """Get user input for selecting an Access Control Policy."""
    ac_policies = fmc.policy.accesspolicy.get()
    policy_map = {}

    print("ACP available in global domain: ")
    for idx, policy in enumerate(ac_policies, start=1):
        policy_map[idx] = {'id': policy['id'], 'name': policy['name']}
        print(f"\t{idx}. {policy['name']}")

    while True:
        try:
            selection_idx = int(input("Enter the number corresponding to the Access Control Policy: "))
            if selection_idx in policy_map:
                return [policy_map[selection_idx]]
            else:
                print("Invalid number. Please enter a valid number.")
        except ValueError:
            print("Invalid input. Please enter a number.")

def export_acp_and_objects(fmc, selection):
    """Export Access Control Policies and related objects to separate JSON files."""
    object_types = {
        'network_objects_all': fmc.object.network.get,
        'network_group_objects_all': fmc.object.networkgroup.get,
        'network_hosts': fmc.object.host.get,
        'network_fqdn': fmc.object.fqdn.get,
        'network_ranges': fmc.object.range.get,
        'port_objects': fmc.object.port.get,
        'port_objects_group': fmc.object.portobjectgroup.get,
        'urls' : fmc.object.url.get,
        'urlgroup' : fmc.object.urlgroup.get
    }

    for obj_type, obj_getter in object_types.items():
        data = obj_getter()
        with open(f"{obj_type}.json", "w") as json_file:
            json.dump(data, json_file, indent=4)

    # Export rules data for each selected Access Control Policy
    for policy in selection:
        rules = fmc.policy.accesspolicy.accessrule.get(policy['id'])
        with open("rules.json", "w") as json_file:
            json.dump(rules, json_file, indent=4)

if __name__ == "__main__":
    # Get user input for FMC credentials
    hostname = input("Enter FMC hostname: ")
    username = input("Enter FMC username: ")
    password = getpass.getpass("Enter FMC password: ")

    # Record the start time
    start_time = time.time()
    # Authenticate with FMC
    fmc = FMC(hostname=hostname, username=username, password=password, domain='Global')

    # Get user selection for Access Control Policies
    acp_selection = get_acp_selection(fmc)

    # Export Access Control Policies and related objects to separate JSON files
    export_acp_and_objects(fmc, acp_selection)

    # Load JSON files and process network objects
    data_list = load_json_files(['network_hosts.json', 'network_fqdn.json', 'network_objects_all.json', 'network_ranges.json', 'network_group_objects_all.json', 'port_objects.json', 'port_objects_group.json', 'urls.json', 'urlgroup.json', 'rules.json'])
    network_group_objects_ip_hashmap = process_network_objects(data_list)
    merge_objects(network_group_objects_ip_hashmap)

    # Process rules data and extract relevant information
    extracted_rules = process_rules(data_list)

    # Generate filename for CSV file
    filename = generate_filename(acp_selection[0]['name'])

    # Write extracted rules to a CSV file
    write_to_csv(extracted_rules, filename)

    ## Record the end time
    end_time = time.time()

    ## Calculate the elapsed time
    elapsed_time = end_time - start_time
    print(f"Process completed in {elapsed_time:.2f} seconds.")
