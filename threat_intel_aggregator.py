# threat_intel_aggregator.py

"""
Threat Intelligence Aggregator

This script uses the Shodan API and additional sources to aggregate threat intelligence data.
"""

import shodan
import requests

# Shodan API key
SHODAN_API_KEY = "YOUR_API_KEY"

# Initialize the Shodan API
api = shodan.Shodan(SHODAN_API_KEY)

# Function to search Shodan for IP addresses
def search_shodan(query):
    """
    Searches Shodan for IP addresses matching the given query.

    Args:
        query (str): The search query to use for Shodan search.

    Returns:
        list: A list of IP addresses matching the search query.
    """
    results = api.search(query)
    return [result['ip_str'] for result in results['matches']]

# Function to get threat intelligence data from IP addresses
def get_threat_intel(ip_addresses):
    """
    Retrieves additional threat intelligence data for the given IP addresses.

    Args:
        ip_addresses (list): A list of IP addresses.

    Returns:
        list: A list of dictionaries containing the threat intelligence data for each IP address.
    """
    threat_intel = []
    for ip in ip_addresses:
        # Perform additional lookups or analysis on each IP
        response = requests.get(f"https://api.ipdata.co/{ip}?api-key=YOUR_IPDATA_KEY")
        data = response.json()
        threat_intel.append({
            "ip": ip,
            "country": data.get("country_name", "Unknown"),
            "asn": data.get("asn", "Unknown"),
            "isp": data.get("asn_organization", "Unknown"),
            "domain": data.get("domain", "Unknown"),
            "ports": data.get("ports", [])
        })
    return threat_intel

# Main execution
if __name__ == "__main__":
    # Example usage
    query = "port:22"  # Replace with your desired Shodan search query
    ip_addresses = search_shodan(query)
    threat_intel = get_threat_intel(ip_addresses)

    # Print the threat intelligence data
    for entry in threat_intel:
        print(f"IP: {entry['ip']}")
        print(f"Country: {entry['country']}")
        print(f"ASN: {entry['asn']}")
        print(f"ISP: {entry['isp']}")
        print(f"Domain: {entry['domain']}")
        print(f"Ports: {', '.join(str(port) for port in entry['ports'])}")
        print("---")
