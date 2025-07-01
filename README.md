🔍 Custom Log Forensic Analyzer
A browser-based forensic application designed to parse and analyze custom log files. Developed with Streamlit, this tool assists cybersecurity professionals, digital investigators, and IT teams in uncovering anomalies in logs through a user-friendly interface and minimal configuration.

🧰 Feature Highlights
📂 Flexible Log Format Support
Handles files in .txt, .log, and .vlog formats.

It intelligently detects and extracts the following elements:

Timestamps

Event Codes (e.g., EVNT:XR-XXXX)

User Identifiers (e.g., usr:username)

IP Addresses (e.g., IP:xxx.xxx.xxx.xxx)

File Paths

Process Identifiers (PIDs)

📈 Interactive Visualization & Analysis
📋 Summary Overview
Displays core metrics: total log entries, unique users, distinct events, and originating IP addresses.

📅 Time-based Event Tracking
Visual representation of event occurrences over 10-second intervals to highlight patterns or irregular spikes.

⚠️ Anomaly Identification
Z-Score Method: Detects statistical deviations.

Isolation Forest: Uses machine learning to identify unusual patterns in data.

🌍 IP-Based Geolocation
Integrates with ipinfo.io to map IP addresses on an interactive world map.

📤 Export Functionality
Parsed results can be downloaded in the following formats:

.csv

.json

.txt

These formats are suitable for reporting, archiving, or additional forensic workflows.

🧪 Sample Log Format
A standard log entry should follow this structure:

arduino
Copy
Edit
[ts:1719835600] EVNT:XR-ACCESS usr:john IP:192.168.1.100 =>/home/docs/file1.txt pid4567
Field breakdown:

ts: Unix timestamp

EVNT: Event category

usr: Username

IP: IP address

=>/: Path to the accessed file

pid: Process ID

💻 Local Setup Instructions
🔧 Prerequisites
Python 3.8 or later

Required Python libraries (see below)

📦 Installation Steps
Install dependencies using:

bash
Copy
Edit
pip install streamlit pandas plotly scikit-learn scipy matplotlib requests
🚀 Run the App
Launch with:

bash
Copy
Edit
streamlit run app.py
Open the URL shown in the terminal (typically http://localhost:8501) in your browser.

📁 Supported Output Formats
You can save the extracted data in:

JSON

CSV

Plain Text

These outputs are ideal for evidence storage, extended analysis, or workflow integration.

📌 Benefits of This Tool
Gain quick insight into system and user actions.

Identify abnormal or suspicious patterns early.

Perform fast log triage with a clean interface.

Export structured logs for deeper investigations.

📸 Dashboard Snapshots
🔹 Timeline View: Time-based event distribution

🔹 Anomaly Detection: Visual alerts for suspicious activity

🔹 IP Mapping: Geographic location of log entries

📜 License
This project is licensed under the MIT License, allowing free use and modification for personal and commercial purposes.

👨‍💻 Developed by
Suvetha Oudearadjou

GitHub: @NaveenSamidurai

Email: naveenca725@gmail.com

