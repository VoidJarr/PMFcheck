# PMFcheck

## Description

This tool analyzes pcap files to report the Protected Management Frames (PMF) status for specified SSIDs or all available SSIDs in the capture. 

## Requirements

- Python 3.10 or higher
- Scapy library

## Installation

1. Clone the repository or download the script:
    ```
    git clone https://github.com/VoidJarr/PMFcheck && cd PMFcheck
    ```
2. (Optional) Create and activate a Python virtual environment:
    ```
    python -m venv venv
    source venv/bin/activate  # On Unix-based systems
    venv\Scripts\activate     # On Windows
    ```
3. Install the required dependency:
    ```
    pip install scapy
    ```

## Usage

Run the script with the following command:
```
python PMFcheck.py <pcap_file> [ssid_file]
```

- `<pcap_file>`: Path to the pcap file for analysis (required). It can be obtained using [`airodump-ng`](https://github.com/aircrack-ng/aircrack-ng) (one of the default file output formats, or with `--output-format pcap`).  
- `[ssid_file]`: Optional path to a file containing SSIDs to check (one per line).

The tool will process the pcap file, and output the PMF status for each relevant SSID.

## Examples

1. Analyze all SSIDs in a pcap file:
    ```
    python PMFcheck.py capture.cap
    ```

2. Analyze specific SSIDs from a file:
    ```
    python PMFcheck.py capture.cap ssids.txt
    ```

   Where `ssids.txt` contains:
   ```
   SSID1
   SSID2
   ```

## Output

Possible PMF statuses are:
- required
- enabled (optional)
- not supported

## Author

VoidJarr

## License

This project is licensed under the MIT License.
