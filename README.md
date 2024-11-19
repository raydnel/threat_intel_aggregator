# Threat Intelligence Aggregator

This simple script uses the Shodan API and additional sources to aggregate threat intelligence data.

# What does it do?
This script aggregates threat intelligence data by using the Shodan API to search for potentially exposed or vulnerable devices on the internet based on a specific query (e.g., devices with open ports).
Enriching the gathered IP addresses with additional data from the IPData API. Such as Country, ASN (Autonomous System Number), ISP (Internet Service Provider), Domain, Ports.

# Use Case
This tool can be used in cybersecurity threat analysis and monitoring to identify potentially vulnerable or malicious devices. Gather contextual information for further investigation or response.
Prioritize threats based on geographic location, ISP, or exposed services.

## Installation

1. Install the required libraries by running the following command in your terminal or command prompt:

`pip install shodan`                                                                                                                                                         
`pip install aiohttp`

2. Replace `"YOUR_API_KEY"` with your actual Shodan API key and `"YOUR_IPDATA_KEY"` with your API key from ipdata.com. I'm storing my API Keys in Environment Variables. 

## Usage

1. Save the script in a file with a `.py` extension, such as `threat_intel_aggregator.py`.

2. Open a terminal or command prompt and navigate to the directory where the script is saved.

3. Run the script using the Python interpreter:

`python threat_intel_aggregator.py`


3. The script will execute, search Shodan for IP addresses matching the specified query, retrieve additional threat intelligence data for each IP, and print the results.

## Customization

You can customize the script by modifying the search query in the `query` variable to search for specific IP addresses or ports.

The script can be extended to incorporate additional sources of threat intelligence data by adding more API calls or data sources.

Remember to keep your API keys secure and not share them publicly.
