# 🛡️ Defense Surveillance Command & Control (DS-C2) Dashboard

A centralized threat monitoring and access intelligence platform built with Streamlit. The DS-C2 Dashboard provides real-time surveillance event analysis, access log monitoring, and threat classification for security operations centers.

## 📋 Features

- **Real-time Event Monitoring**: Track motion detection, loitering, and directional violations across multiple zones
- **Event Severity Classification**: Automatic threat level assessment (HIGH, MEDIUM, LOW) based on event type and location
- **Multi-source Log Integration**: Consolidate data from IVA (Intelligent Video Analytics) logs and access control systems
- **Interactive Filtering**: Filter events by type and zone for targeted analysis
- **Dark-themed UI**: Purpose-built dashboard interface optimized for 24/7 monitoring
- **Auto-refresh Capability**: Configurable automatic data refresh for continuous surveillance
- **Plotly Visualizations**: Interactive charts and graphs for threat pattern analysis

## 🚀 Quick Start

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

## 📊 Data Format

### IVA Logs (iva_logs.csv)
Expected columns:
- `event_type` - Type of event (Motion, Loitering, Wrong Direction, etc.)
- `zone` - Security zone where event occurred
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

## 🎨 Customization

### Severity Classification
Modify the `classify_severity()` function in `main.py` to adjust threat level criteria:
- HIGH severity: Loitering in restricted zones (Gate B, Zone C)
- MEDIUM severity: Wrong Direction violations
- LOW severity: General motion detection

### Dashboard Styling
The dashboard uses CSS custom properties for theming. Edit the style section in `main.py` to customize colors and appearance.

### Refresh Interval
Configure the auto-refresh interval in the sidebar (default: 30 seconds).

## 🔧 Dependencies

- **streamlit** - Web application framework
- **pandas** - Data manipulation and analysis
- **plotly** - Interactive visualizations
- **python-dateutil** - Date/time utilities

See `requirements.txt` for complete dependency list.

## 📈 Usage Examples

1. **Monitor Current Threats**: View real-time HIGH severity events in the main dashboard
2. **Historical Analysis**: Filter events by date range and zone to identify patterns
3. **Access Intelligence**: Review access logs to correlate with surveillance events
4. **System Status**: Check system time and event counts in the sidebar

## 🔒 Security Considerations

- Deploy behind secure authentication layer for production use
- Restrict access to authorized security personnel only
- Use HTTPS for all connections
- Implement proper data retention policies
- Regularly audit access logs

## 📝 Logging

The dashboard logs all activity to `system.log`. Check this file for debugging and audit trails.

## 🐛 Troubleshooting

**Issue**: "IVA logs file not found"
- Solution: Ensure `iva_logs.csv` exists in the project directory

**Issue**: "Access logs file not found"
- Solution: Ensure `access_logs.json` exists in the project directory

**Issue**: Dashboard not refreshing
- Solution: Click "Refresh Now" button or restart the application

## 📄 License

[Add your license here]

## 👥 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues.

## 📞 Support

For issues, questions, or feature requests, please contact the development team or open an issue in the repository.

---

**Last Updated**: February 2026  
**Version**: 1.0.0
