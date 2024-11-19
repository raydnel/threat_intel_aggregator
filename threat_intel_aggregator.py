"""
Threat Intelligence Aggregator

This script uses the Shodan API and additional sources to aggregate threat intelligence data.
"""

import os
import shodan
import requests
import asyncio
import aiohttp
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load API keys from environment variables
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
IPDATA_KEY = os.getenv("IPDATA_KEY")

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
    try:
        logger.info(f"Searching Shodan with query: {query}")
        results = api.search(query)
        return [result['ip_str'] for result in results.get('matches', [])]
    except shodan.APIError as e:
        logger.error(f"Shodan API error: {e}")
        return []

# Asynchronous function to fetch threat intelligence data for an IP address
async def fetch_ip_data(ip, session):
    """
    Fetches threat intelligence data for a single IP address.

    Args:
        ip (str): The IP address to fetch data for.
        session (aiohttp.ClientSession): An active aiohttp session.

    Returns:
        dict: A dictionary with threat intelligence data for the IP.
    """
    url = f"https://api.ipdata.co/{ip}?api-key={IPDATA_KEY}"
    try:
        async with session.get(url) as response:
            response.raise_for_status()
            data = await response.json()
            return {
                "ip": ip,
                "country": data.get("country_name", "Unknown"),
                "asn": data.get("asn", "Unknown"),
                "isp": data.get("asn_organization", "Unknown"),
                "domain": data.get("domain", "Unknown"),
                "ports": data.get("ports", [])
            }
    except aiohttp.ClientError as e:
        logger.error(f"Error fetching data for {ip}: {e}")
        return {"ip": ip, "error": "Failed to fetch data"}

# Asynchronous function to process multiple IP addresses
async def get_threat_intel(ip_addresses):
    """
    Retrieves threat intelligence data for a list of IP addresses asynchronously.

    Args:
        ip_addresses (list): A list of IP addresses.

    Returns:
        list: A list of dictionaries containing threat intelligence data.
    """
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_ip_data(ip, session) for ip in ip_addresses]
        return await asyncio.gather(*tasks)

# Main execution
if __name__ == "__main__":
    if not SHODAN_API_KEY or not IPDATA_KEY:
        logger.error("API keys are missing. Ensure SHODAN_API_KEY and IPDATA_KEY are set as environment variables.")
        exit(1)

    # Example usage
    query = "port:22"  # Replace with your desired Shodan search query
    ip_addresses = search_shodan(query)

    if ip_addresses:
        logger.info(f"Found {len(ip_addresses)} IP addresses. Fetching threat intelligence...")
        threat_intel = asyncio.run(get_threat_intel(ip_addresses))

        # Print the threat intelligence data
        for entry in threat_intel:
            print(f"IP: {entry.get('ip')}")
            print(f"Country: {entry.get('country', 'N/A')}")
            print(f"ASN: {entry.get('asn', 'N/A')}")
            print(f"ISP: {entry.get('isp', 'N/A')}")
            print(f"Domain: {entry.get('domain', 'N/A')}")
            print(f"Ports: {', '.join(str(port) for port in entry.get('ports', []))}")
            print("---")
    else:
        logger.warning("No IP addresses found for the given query.")
