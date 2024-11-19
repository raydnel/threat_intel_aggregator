# Threat Intelligence Aggregator

This simple script uses the Shodan API and additional sources to aggregate threat intelligence data.

## Installation

1. Install the required libraries by running the following command in your terminal or command prompt:

pip install shodan


2. Replace `"YOUR_API_KEY"` with your actual Shodan API key and `"YOUR_IPDATA_KEY"` with your API key from ipdata.com

## Usage

1. Save the script in a file with a `.py` extension, such as `threat_intel_aggregator.py`.

2. Open a terminal or command prompt and navigate to the directory where the script is saved.

3. Run the script using the Python interpreter:

python threat_intel_aggregator.py


3. The script will execute, search Shodan for IP addresses matching the specified query, retrieve additional threat intelligence data for each IP, and print the results.

## Customization

You can customize the script by modifying the search query in the `query` variable to search for specific IP addresses or ports.

The script can be extended to incorporate additional sources of threat intelligence data by adding more API calls or data sources.

Remember to keep your API keys secure and not share them publicly.
