# 🛡️ Defense Surveillance Command & Control (DS-C2) Dashboard

A centralized threat monitoring and access intelligence platform built with Streamlit. The DS-C2 Dashboard provides real-time surveillance event analysis, access log monitoring, and threat classification for security operations centers.

##  Features

- **Real-time Event Monitoring**: Track motion detection, loitering, and directional violations across multiple zones
- **Event Severity Classification**: Automatic threat level assessment (HIGH, MEDIUM, LOW) based on event type and location
- **Multi-source Log Integration**: Consolidate data from IVA (Intelligent Video Analytics) logs and access control systems
- **Interactive Filtering**: Filter events by type and zone for targeted analysis
- **Plotly Visualisations**: Interactive charts and graphs for threat pattern analysis

##  Quick Start

### Prerequisites

- Python 3.8+
- pip (Python package manager)

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd C2-Dashboard
```

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

3. Ensure your data files are in the project directory:
   - `iva_logs.csv` - IVA event logs
   - `access_logs.json` - Access control logs

### Running the Dashboard

```bash
streamlit run main.py
```

The dashboard will open in your default browser at `http://localhost:8501`

## 📁 Project Structure

```
C2-Dashboard/
├── main.py                 # Main Streamlit application
├── iva_logs.csv           # Intelligent Video Analytics logs
├── access_logs.json       # Access control system logs
├── README.md              # This file
└── requirements.txt       # Python dependencies
```

##  Data Format

### IVA Logs (iva_logs.csv)
Expected columns:
- `event_type` - Type of event (Motion, Loitering, Wrong Direction, etc.)
- `zone` - Security zone where the event occurred
- `timestamp` - When the event was detected
- Additional context fields as needed

### Access Logs (access_logs.json)
Expected format:
```json
[
  {
    "timestamp": "2026-02-15 10:30:45",
    "access_point": "Gate B",
    "status": "GRANTED",
    ...
  }
]
```



##  Dependencies

- **streamlit** - Web application framework
- **pandas** - Data manipulation and analysis
- **plotly** - Interactive visualizations
- **python-dateutil** - Date/time utilities

See `requirements.txt` for the complete dependency list.

## Usage Examples

1. **Monitor Current Threats**: View real-time HIGH severity events in the main dashboard
2. **Historical Analysis**: Filter events by date range and zone to identify patterns
3. **Access Intelligence**: Review access logs to correlate with surveillance events
4. **System Status**: Check system time and event counts in the sidebar



## Troubleshooting

**Issue**: "IVA logs file not found"
- Solution: Ensure `iva_logs.csv` exists in the project directory

**Issue**: "Access logs file not found"
- Solution: Ensure `access_logs.json` exists in the project directory

**Issue**: Dashboard not refreshing
- Solution: Click "Refresh Now" button or restart the application

##  License
- MIT license
---

**Version**: 1.0.0

