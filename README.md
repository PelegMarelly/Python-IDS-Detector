# Python IDS Detector

A network Intrusion Detection System (IDS) written in Python that detects TCP SYN port scans in real-time and alerts the user via a GUI pop-up.

## Getting Started

### Prerequisites

* **Python 3.x** installed on the host machine.
* **Scapy** library. Install via pip:
    ```bash
    pip install scapy
    ```
* **Windows Users:** **Npcap** must be installed to allow packet capturing. Ensure the option *"Install Npcap in WinPcap API-compatible Mode"* is selected during installation.

### Installation

1.  Clone the repository to your local machine.
2.  Navigate to the project directory.

## Usage Instructions

To demonstrate the system's capabilities, you will need two separate terminal instances: one to run the defense mechanism (IDS) and one to simulate the attack.

### 1. Deploy the Detector

The detection script requires access to the network interface, which mandates administrative privileges.

1.  Open a terminal or command prompt as **Administrator** (or use `sudo` on Linux).
2.  Execute the detector script:
    ```bash
    python scan_detector.py
    ```
3.  The system will initialize and begin monitoring network traffic for TCP SYN packets.

### 2. Simulate a Port Scan

The repository includes an `attacker.py` script designed to simulate a rapid port scan for testing purposes.

1.  Open a **separate** terminal window.
2.  Edit `attacker.py` and ensure the `target_ip` variable is set to your machine's **actual LAN IP address** (e.g., `192.168.1.15`).
    > **Note:** Do not use `127.0.0.1` or `localhost`, as the packet sniffer may not capture loopback traffic depending on the OS configuration.
3.  Run the attack simulation:
    ```bash
    python attacker.py
    ```

### Expected Behavior

Upon execution of the attack simulation, the IDS will detect the rapid succession of connection attempts.

* **Console Output:** The detector terminal will log the source IP and the number of unique ports scanned.
* **GUI Alert:** A pop-up warning window will appear on the screen, notifying the user of the detected port scan activity.
