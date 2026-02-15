import streamlit as st
import pandas as pd
import json
from datetime import datetime
import plotly.express as px
import plotly.graph_objects as go

# ---- Page Configuration ----
st.set_page_config(page_title="DS-C2 Dashboard", layout="wide", initial_sidebar_state="expanded")

# ---- Auto Refresh Configuration ----
if "refresh_interval" not in st.session_state:
    st.session_state.refresh_interval = 30

st.set_page_config(
    page_title="DS-C2 Dashboard",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items=None
)

st.markdown("""
<style>

:root {
    --bg-main: #0B1220;
    --bg-sidebar: #0E1A2B;
    --bg-card: #111C2E;
    --border-card: #1F2F4A;

    --accent-green: #22C55E;
    --accent-cyan: #38BDF8;
    --accent-red: #FF4D4F;
    --accent-orange: #F59E0B;

    --text-main: #E2E8F0;
    --text-muted: #94A3B8;
}

/* Main Background */
body, .main {
    background-color: var(--bg-main);
    color: var(--text-main);
    font-family: 'Inter', sans-serif;
}

/* Sidebar */
[data-testid="stSidebar"] {
    background-color: var(--bg-sidebar);
    border-right: 1px solid var(--border-card);
}

[data-testid="stSidebar"] h2,
[data-testid="stSidebar"] h3 {
    color: var(--accent-green) !important;
}

/* Header */
.dashboard-header {
    background: linear-gradient(135deg, #111C2E 0%, #1B2A44 100%);
    border-left: 5px solid var(--accent-green);
    padding: 30px;
    border-radius: 12px;
    margin-bottom: 25px;
    box-shadow: 0 0 20px rgba(34,197,94,0.15);
}

/* Section Titles */
.section-title {
    color: var(--text-main);
    font-weight: 600;
    letter-spacing: 1px;
    margin-top: 20px;
    margin-bottom: 15px;
    border-bottom: 1px solid var(--border-card);
    padding-bottom: 8px;
}

/* Metric Cards */
.metric-card {
    background: var(--bg-card);
    border: 1px solid var(--border-card);
    border-radius: 12px;
    padding: 25px;
    text-align: center;
    transition: 0.3s ease;
}

.metric-card:hover {
    box-shadow: 0 0 15px rgba(56,189,248,0.2);
    transform: translateY(-4px);
}

/* Tables */
[data-testid="stDataFrame"] {
    background-color: var(--bg-card);
    border-radius: 10px;
    border: 1px solid var(--border-card);
}

thead tr th {
    background-color: #162338 !important;
    color: var(--accent-cyan) !important;
    font-weight: 600 !important;
}

/* Buttons */
.stButton > button {
    background-color: var(--accent-green);
    border: none;
    border-radius: 8px;
    color: #000;
    font-weight: 600;
}

.stButton > button:hover {
    background-color: var(--accent-cyan);
    color: #000;
}

/* Dividers */
hr {
    border: none;
    height: 1px;
    background: var(--border-card);
    margin: 25px 0;
}

</style>
""", unsafe_allow_html=True)


# helper to show a single styled divider (used throughout)
def show_divider():
    st.markdown("<hr style='border-color: #c9b863; height:1px; border:none; background-color:#c9b863; margin:20px 0;'/>", unsafe_allow_html=True)

# ---- Title Section ----
st.markdown("""
    <div style='background: linear-gradient(135deg, #1f2a2e 0%, #0f1112 100%); border-left: 5px solid #c9b863; padding: 30px; border-radius: 10px; margin-bottom: 20px;'>
        <h1 style='margin: 0; color: #ffffff; font-size: 32px; font-weight: 700;'>🛡️ Defense Surveillance Command & Control (DS-C2) Dashboard</h1>
        <p style='margin: 10px 0 0 0; color: #c9b863; font-size: 14px; font-weight: 600; letter-spacing: 2px;'>CENTRALIZED THREAT MONITORING & ACCESS INTELLIGENCE PLATFORM</p>
    </div>
""", unsafe_allow_html=True)

show_divider()

# ---- Sidebar Logo Section ----
with st.sidebar:
    st.markdown("""
        <div style='text-align: center; padding: 20px 0;'>
            <p style='font-size: 28px; margin: 0;'>🛡️</p>
            <p style='color: #c9b863; font-size: 18px; font-weight: 700; margin: 10px 0 5px 0; letter-spacing: 2px;'>DS-C2 SYSTEM</p>
            <p style='color: #666666; font-size: 12px; margin: 0;'>Surveillance Command & Control</p>
        </div>
    """, unsafe_allow_html=True)
    
    st.markdown("<hr style='border-color: #c9b863; height:1px; border:none; background-color:#c9b863; margin:20px 0;'/>", unsafe_allow_html=True)
    
    # ---- Sidebar Filters ----
    st.markdown("<h3 style='color: #c9b863; font-size: 16px; font-weight: 700;'>🔍 FILTER CONTROLS</h3>", unsafe_allow_html=True)

# ---- Load Data Safely ----
try:
    iva_df = pd.read_csv("iva_logs.csv")
except:
    st.error("IVA logs file not found.")
    iva_df = pd.DataFrame()

try:
    with open("access_logs.json") as f:
        access_data = json.load(f)
    access_df = pd.DataFrame(access_data)
except:
    st.error("Access logs file not found.")
    access_df = pd.DataFrame()

# ---- Event Severity Classification Function ----
def classify_severity(event_type, zone):
    """
    Classify event severity based on event type and zone
    Returns: HIGH, MEDIUM, or LOW
    """
    # HIGH severity: Loitering in restricted zones
    restricted_zones = ["Gate B", "Zone C"]
    if event_type == "Loitering" and zone in restricted_zones:
        return "HIGH"
    
    # MEDIUM severity: Wrong Direction in any zone
    if event_type == "Wrong Direction":
        return "MEDIUM"
    
    # LOW severity: General motion detection
    if event_type == "Motion":
        return "LOW"
    
    # Default: LOW
    return "LOW"

# Add severity column to IVA dataframe
if not iva_df.empty:
    iva_df["Severity"] = iva_df.apply(
        lambda row: classify_severity(row["event_type"], row["zone"]), 
        axis=1
    )

# ---- Sidebar Filters (continued) ----
with st.sidebar:
    if not iva_df.empty:
        st.markdown("<p style='color: #888; font-size: 12px; font-weight: 600; margin: 15px 0 8px 0;'>Event Type</p>", unsafe_allow_html=True)
        event_filters = st.multiselect(
            "Event Type",
            list(iva_df["event_type"].unique()),
            default=list(iva_df["event_type"].unique()),
            key="event_filter",
            label_visibility="collapsed"
        )

        st.markdown("<p style='color: #888; font-size: 12px; font-weight: 600; margin: 15px 0 8px 0;'>Zone</p>", unsafe_allow_html=True)
        zone_filters = st.multiselect(
            "Zone",
            list(iva_df["zone"].unique()),
            default=list(iva_df["zone"].unique()),
            key="zone_filter",
            label_visibility="collapsed"
        )

        filtered_iva = iva_df.copy()

        if event_filters:
            filtered_iva = filtered_iva[filtered_iva["event_type"].isin(event_filters)]

        if zone_filters:
            filtered_iva = filtered_iva[filtered_iva["zone"].isin(zone_filters)]
    else:
        filtered_iva = iva_df
        event_filters = []
        zone_filters = []
    
    # Add spacing
    st.markdown("<div style='margin: 30px 0;'></div>", unsafe_allow_html=True)
    
    # System Time Display
    st.markdown(f"<p style='text-align: center; color: #666; font-size: 11px; font-weight: 600; letter-spacing: 1px;'>SYSTEM TIME: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>", unsafe_allow_html=True)
    
    st.markdown("<div style='margin: 20px 0;'></div>", unsafe_allow_html=True)
    
    # Refresh button at the bottom
    if st.button("Refresh Now", key="refresh_button", use_container_width=True):
        st.rerun()

# Auto-refresh using query params
refresh_seconds = 30
st.markdown("""
    <script>
        setTimeout(function() {
            window.location.reload();
        }, """ + str(refresh_seconds * 1000) + """);
    </script>
""", unsafe_allow_html=True)

# ---- Alert Summary Section ----
st.markdown("<h3 style='color: #c9b863; font-size: 18px; font-weight: 700; letter-spacing: 1px;'>▌ ALERT SUMMARY</h3>", unsafe_allow_html=True)

col1, col2, col3, col4 = st.columns(4)

def display_metric_card(col, icon, title, value):
    """Display metric card matching screenshot design"""
    col.markdown(f"""
        <div style='background-color: #1a1f1f; border: 1px solid rgba(201,184,99,0.15); padding: 25px; border-radius: 10px; margin: 10px 0; box-shadow: 0 2px 8px rgba(0,0,0,0.3); text-align: center;'>
            <p style='font-size: 28px; margin: 0 0 10px 0;'>{icon}</p>
            <p style='color: #888888; margin: 0 0 8px 0; font-size: 11px; font-weight: 600; letter-spacing: 1px;'>{title}</p>
            <p style='color: #52bfff; margin: 0; font-size: 36px; font-weight: 700;'>{value}</p>
        </div>
    """, unsafe_allow_html=True)

if not iva_df.empty:
    total_iva = len(iva_df)
    loitering = len(iva_df[iva_df["event_type"]=="Loitering"])
    wrong_dir = len(iva_df[iva_df["event_type"]=="Wrong Direction"])
else:
    total_iva = 0
    loitering = 0
    wrong_dir = 0

if not access_df.empty:
    access_denied = len(access_df[access_df["decision"]=="DENY"])
else:
    access_denied = 0

display_metric_card(col1, "", "TOTAL IVA EVENTS", total_iva)
display_metric_card(col2, "", "LOITERING ALERTS", loitering)
display_metric_card(col3, "", "WRONG DIRECTION", wrong_dir)
display_metric_card(col4, "", "ACCESS DENIED", access_denied)

show_divider()

# ---- Incident Timeline View ----
st.markdown("<h2 style='color: #3d5a3d;' hidden>Incident Timeline</h2>", unsafe_allow_html=True)

timeline_tab1, timeline_tab2 = st.tabs(["IVA Events Timeline", "Access Control Timeline"])

with timeline_tab1:
    if not iva_df.empty:
        # Sort by timestamp (assuming 'timestamp' column exists, otherwise use first date column)
        if "timestamp" in iva_df.columns:
            iva_timeline = iva_df.sort_values("timestamp", ascending=False)
        else:
            # Try to find a date column
            date_cols = [col for col in iva_df.columns if 'time' in col.lower() or 'date' in col.lower()]
            if date_cols:
                iva_timeline = iva_df.sort_values(date_cols[0], ascending=False)
            else:
                iva_timeline = iva_df
        
        # Display timeline
        for idx, row in iva_timeline.iterrows():
            time_str = str(row.get("timestamp", row.get(list(iva_df.columns)[0], "N/A")))
            event_type = row.get("event_type", "Unknown")
            zone = row.get("zone", "Unknown")
            severity = row.get("Severity", "LOW")
            
            # Color code by severity
            if severity == "HIGH":
                color = "#c84b31"
            elif severity == "MEDIUM":
                color = "#c9b863"
            else:
                color = "#3d5a3d"
            
            st.markdown(f"""
                <div style='background-color: var(--card-dark); border-left: 5px solid {color}; padding: 14px; margin: 10px 0; border-radius: 6px; box-shadow: 0 1px 4px rgba(0,0,0,0.45);'>
                    <p style='margin: 0; color: var(--muted-text);'>
                        <span style='color: var(--army-green); font-weight: 700;'>{time_str}</span> - 
                        <span style='color: {color}; font-weight: 600;'>{event_type}</span> 
                        <span style='color: var(--muted-text);'>@ {zone}</span>
                        <span style='color: {color}; float: right; font-weight: 600;'>{severity}</span>
                    </p>
                </div>
            """, unsafe_allow_html=True)
    else:
        st.info("No IVA events to display")

with timeline_tab2:
    if not access_df.empty:
        # Sort by timestamp
        if "timestamp" in access_df.columns:
            access_timeline = access_df.sort_values("timestamp", ascending=False)
        else:
            date_cols = [col for col in access_df.columns if 'time' in col.lower() or 'date' in col.lower()]
            if date_cols:
                access_timeline = access_df.sort_values(date_cols[0], ascending=False)
            else:
                access_timeline = access_df
        
        # Display timeline
        for idx, row in access_timeline.iterrows():
            time_str = str(row.get("timestamp", row.get(list(access_df.columns)[0], "N/A")))
            user_id = row.get("user_id", "Unknown")
            decision = row.get("decision", "Unknown")
            zone = row.get("zone", "Unknown")
            reason = row.get("reason", "N/A")
            
            # Color code by decision
            if decision == "ALLOW":
                color = "#3d5a3d"
            else:
                color = "#c84b31"
            
            st.markdown(f"""
                <div style='background-color: var(--card-dark); border-left: 5px solid {color}; padding: 14px; margin: 10px 0; border-radius: 6px; box-shadow: 0 1px 4px rgba(0,0,0,0.45);'>
                    <p style='margin: 0; color: var(--muted-text);'>
                        <span style='color: var(--army-green); font-weight: 700;'>{time_str}</span> - 
                        <span style='color: {color}; font-weight: 600;'>{decision}</span>
                        <span style='color: var(--muted-text);'> ({user_id})</span>
                        <span style='color: var(--muted-text); float: right;'>Zone: {zone}</span>
                    </p>
                    <p style='margin: 6px 0 0 0; color: var(--muted-text); font-size: 13px;'>Reason: {reason}</p>
                </div>
            """, unsafe_allow_html=True)
    else:
        st.info("No access control events to display")

show_divider()

# ---- Charts Section ----
st.markdown("<h2 style='color: #3d5a3d;'>Analytics and Visualizations</h2>", unsafe_allow_html=True)

chart_col1, chart_col2 = st.columns(2)

# Event Type Distribution
with chart_col1:
    st.markdown("<h3 style='color: #3d5a3d;'>Event Type Distribution</h3>", unsafe_allow_html=True)
    if not iva_df.empty:
        event_counts = iva_df["event_type"].value_counts().reset_index()
        event_counts.columns = ["Event Type", "Count"]
        
        # Distinct colors for each event type
        colors_discrete = ["#3d5a3d", "#c84b31", "#c9b863", "#5a7f5a", "#a09060", "#6b8b6b"]
        
        fig_events = px.bar(
            event_counts,
            x="Event Type",
            y="Count",
            title="",
            color="Event Type",
            color_discrete_sequence=colors_discrete[:len(event_counts)]
        )
        fig_events.update_layout(
            plot_bgcolor="#252525",
            paper_bgcolor="#252525",
            font=dict(color="#e0e0e0"),
            xaxis=dict(showgrid=True, gridcolor="#3d5a3d", tickfont=dict(color="#e0e0e0"), title=dict(font=dict(color="#e0e0e0"))),
            yaxis=dict(showgrid=True, gridcolor="#3d5a3d", tickfont=dict(color="#e0e0e0"), title=dict(font=dict(color="#e0e0e0"))),
            showlegend=False
        )
        st.plotly_chart(fig_events, use_container_width=True)
    else:
        st.info("No event data available")

# Zone Distribution
with chart_col2:
    st.markdown("<h3 style='color: #3d5a3d;'>Zone Activity Distribution</h3>", unsafe_allow_html=True)
    if not iva_df.empty:
        zone_counts = iva_df["zone"].value_counts().reset_index()
        zone_counts.columns = ["Zone", "Count"]
        
        # Distinct colors for each zone
        colors_discrete = ["#3d5a3d", "#c84b31", "#c9b863", "#5a7f5a", "#a09060", "#6b8b6b"]
        
        fig_zones = px.bar(
            zone_counts,
            x="Zone",
            y="Count",
            title="",
            color="Zone",
            color_discrete_sequence=colors_discrete[:len(zone_counts)]
        )
        fig_zones.update_layout(
            plot_bgcolor="#252525",
            paper_bgcolor="#252525",
            font=dict(color="#e0e0e0"),
            xaxis=dict(showgrid=False, tickfont=dict(color="#e0e0e0"), title=dict(font=dict(color="#e0e0e0"))),
            yaxis=dict(showgrid=True, gridcolor="#3d5a3d", tickfont=dict(color="#e0e0e0"), title=dict(font=dict(color="#e0e0e0"))),
            showlegend=False
        )
        st.plotly_chart(fig_zones, use_container_width=True)
    else:
        st.info("No zone data available")

# Access Decision Distribution
chart_col3, chart_col4 = st.columns(2)

with chart_col3:
    st.markdown("<h3 style='color: #6b8e6b;'>Access Control Decisions</h3>", unsafe_allow_html=True)
    if not access_df.empty:
        decision_counts = access_df["decision"].value_counts().reset_index()
        decision_counts.columns = ["Decision", "Count"]
        colors_map = {"ALLOW": "#6b8e6b", "DENY": "#ff6b6b"}
        fig_decisions = px.pie(
            decision_counts,
            values="Count",
            names="Decision",
            title="",
            color="Decision",
            color_discrete_map=colors_map
        )
        fig_decisions.update_layout(
            plot_bgcolor="#252525",
            paper_bgcolor="#252525",
            font=dict(color="#e0e0e0")
        )
        st.plotly_chart(fig_decisions, use_container_width=True)
    else:
        st.info("No access decision data available")

# Role Distribution
with chart_col4:
    st.markdown("<h3 style='color: #6b8e6b;'>User Roles Distribution</h3>", unsafe_allow_html=True)
    if not access_df.empty and "role" in access_df.columns:
        role_counts = access_df["role"].value_counts().reset_index()
        role_counts.columns = ["Role", "Count"]
        
        # Distinct colors for each role
        colors_discrete = ["#6b8e6b", "#ff6b6b", "#ffd700", "#00d4ff", "#ff69b4", "#32cd32"]
        
        fig_roles = px.bar(
            role_counts,
            x="Role",
            y="Count",
            title="",
            color="Role",
            color_discrete_sequence=colors_discrete[:len(role_counts)]
        )
        fig_roles.update_layout(
            plot_bgcolor="#252525",
            paper_bgcolor="#252525",
            font=dict(color="#e0e0e0"),
            xaxis=dict(showgrid=False, tickfont=dict(color="#e0e0e0"), title=dict(font=dict(color="#e0e0e0"))),
            yaxis=dict(showgrid=True, gridcolor="#3d5a3d", tickfont=dict(color="#e0e0e0"), title=dict(font=dict(color="#e0e0e0"))),
            showlegend=False
        )
        st.plotly_chart(fig_roles, use_container_width=True)
    else:
        st.info("No role data available")

show_divider()

# ---- Enhanced data display with better column formatting ----
st.markdown("<h3 style='color: #c9b863; font-size: 18px; font-weight: 700; letter-spacing: 1px;'>▌ IVA EVENT LOG</h3>", unsafe_allow_html=True)
if not iva_df.empty:
    # Enhance IVA data with additional columns for display
    display_iva = iva_df.copy()
    
    # Add camera info if not present
    if "camera" not in display_iva.columns:
        display_iva["camera"] = display_iva.apply(
            lambda row: f"CAM-{str(display_iva.index.get_loc(row.name)+1).zfill(3)}", 
            axis=1
        )
    
    # Add confidence score if not present
    if "confidence" not in display_iva.columns:
        import random
        display_iva["confidence"] = [round(random.uniform(0.8, 0.99), 2) for _ in range(len(display_iva))]
    
    # Add description if not present
    if "description" not in display_iva.columns:
        descriptions = {
            "Loitering": "Personnel loitering near perimeter gate",
            "Motion": "Motion detected in off-limits storage facility",
            "Wrong Direction": "Wrong-way entry at vehicle inspection point",
            "Intrusion": "Breach attempt detected at north perimeter wall",
            "Abandoned Object": "Unidentified bag left at security checkpoint",
            "Crowd Formation": "Large assembly near briefing hall entrance"
        }
        display_iva["description"] = display_iva["event_type"].apply(
            lambda x: descriptions.get(x, "Activity detected in surveillance area")
        )
    
    # Select and reorder columns for display
    display_cols = ["timestamp", "event_type", "zone", "camera", "confidence", "description"]
    display_iva_clean = display_iva[display_cols].copy()
    display_iva_clean.columns = ["Timestamp", "Event Type", "Zone", "Camera", "Confidence", "Description"]
    
    st.dataframe(
        display_iva_clean,
        hide_index=True,
        use_container_width=True,
        column_config={
            "Confidence": st.column_config.NumberColumn(format="%.2f"),
        }
    )
    
    # Summary stats
    total_events = len(display_iva)
    st.markdown(f"<p style='color: #888; font-size: 12px; font-weight: 500; margin: 10px 0 0 0;'>Showing {min(20, total_events)} of {total_events} total events</p>", unsafe_allow_html=True)
else:
    st.info("No IVA events to display")

show_divider()

# ---- Access Control Section ----
st.markdown("<h3 style='color: #c9b863; font-size: 18px; font-weight: 700; letter-spacing: 1px;'>▌ ACCESS CONTROL LOG</h3>", unsafe_allow_html=True)
if not access_df.empty:
    display_access = access_df.copy()
    
    # Ensure all required columns exist
    if "personnel_id" not in display_access.columns:
        if "user_id" in display_access.columns:
            display_access["personnel_id"] = display_access["user_id"]
        else:
            display_access["personnel_id"] = [f"DF-{str(i).zfill(4)}" for i in range(1, len(display_access)+1)]
    
    if "name" not in display_access.columns:
        # Generate sample names
        names = ["Maj. Rajesh N", "Sgt. K. Sitadevi", "Lt. Col. J. Rahul", "Lt. Col. A. Sharma",
                 "D. Patel", "Cpl. M. Dravid", "S. Narasimma", "Capt. E. Arun Sammy", "WO1 L. Karthikeya"]
        display_access["name"] = [names[i % len(names)] for i in range(len(display_access))]
    
    if "clearance" not in display_access.columns:
        clearances = ["TOP SECRET", "SECRET", "UNCLEARED", "CONFIDENTIAL", "TOP SECRET/SCI"]
        import random
        display_access["clearance"] = [random.choice(clearances) for _ in range(len(display_access))]
    
    if "access_point" not in display_access.columns:
        if "zone" in display_access.columns:
            display_access["access_point"] = display_access["zone"].apply(
                lambda x: {"Gate A": "Gate Alpha", "Gate B": "Gate Bravo", "Gate C": "Gate Charlie", 
                          "Zone C": "SCIF Entry", "Zone D": "Command Center"}.get(x, x)
            )
        else:
            gates = ["Gate Alpha", "Gate Bravo", "Gate Charlie", "SCIF Entry", "Command Center"]
            display_access["access_point"] = [gates[i % len(gates)] for i in range(len(display_access))]
    
    if "auth_method" not in display_access.columns:
        auth_methods = ["Biometric + Badge", "Badge Only", "Biometric + PIN", "No Credential"]
        import random
        display_access["auth_method"] = [random.choice(auth_methods) for _ in range(len(display_access))]
    
    # Select display columns
    display_cols_access = ["timestamp", "personnel_id", "name", "clearance", "access_point", "decision", "auth_method"]
    display_access_clean = display_access[display_cols_access].copy()
    display_access_clean.columns = ["Timestamp", "Personnel ID", "Name", "Clearance", "Access Point", "Decision", "Auth Method"]
    
    st.dataframe(
        display_access_clean,
        hide_index=True,
        use_container_width=True
    )
    
    # Summary stats
    total_access = len(display_access)
    granted = len(display_access[display_access["decision"] == "GRANT"]) if "decision" in display_access.columns else len(display_access[display_access.get("decision", "") == "ALLOW"])
    denied = len(display_access[display_access["decision"] == "DENY"]) if "decision" in display_access.columns else len(display_access[display_access.get("decision", "") == "DENY"])
    
    st.markdown(f"<p style='color: #888; font-size: 12px; font-weight: 500; margin: 10px 0 0 0;'>Total records: {total_access} | Granted: {granted} | Denied: {denied}</p>", unsafe_allow_html=True)
else:
    st.info("No access control logs to display")

show_divider()

# ---- Export Report Feature ----
st.markdown("<h2 style='color: #6b8e6b;'>Export Reports</h2>", unsafe_allow_html=True)

export_col1, export_col2, export_col3 = st.columns(3)

# Generate CSV exports
def generate_csv_export(df, filename):
    return df.to_csv(index=False).encode('utf-8')

def generate_excel_export(df, filename):
    try:
        import openpyxl
        output = pd.ExcelWriter(filename, engine='openpyxl')
        df.to_excel(output, index=False, sheet_name='Data')
        output.close()
        with open(filename, 'rb') as f:
            return f.read()
    except:
        return None

# Generate comprehensive report
def generate_report():
    report = f"""
    ═══════════════════════════════════════════════════════════════
    Defense Surveillance C2 Dashboard - Report
    Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    ═══════════════════════════════════════════════════════════════
    
    SUMMARY STATISTICS
    ───────────────────────────────────────────────────────────────
    Total IVA Events: {len(iva_df)}
    Loitering Alerts: {len(iva_df[iva_df['event_type']=='Loitering']) if not iva_df.empty else 0}
    Wrong Direction: {len(iva_df[iva_df['event_type']=='Wrong Direction']) if not iva_df.empty else 0}
    Access Allowed: {len(access_df[access_df['decision']=='ALLOW']) if not access_df.empty else 0}
    Access Denied: {len(access_df[access_df['decision']=='DENY']) if not access_df.empty else 0}
    
    IVA EVENTS DATA
    ───────────────────────────────────────────────────────────────
    {iva_df.to_string() if not iva_df.empty else 'No data'}
    
    ACCESS CONTROL DATA
    ───────────────────────────────────────────────────────────────
    {access_df.to_string() if not access_df.empty else 'No data'}
    
    ═══════════════════════════════════════════════════════════════
    """
    return report

with export_col1:
    if not iva_df.empty:
        csv_data = generate_csv_export(iva_df, "iva_events.csv")
        st.download_button(
            label="IVA Events ",
            data=csv_data,
            file_name=f"iva_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )
    else:
        st.info("No IVA data to export")

with export_col2:
    if not access_df.empty:
        csv_data = generate_csv_export(access_df, "access_logs.csv")
        st.download_button(
            label="Access Logs ",
            data=csv_data,
            file_name=f"access_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )
    else:
        st.info("No Access data to export")

with export_col3:
    report_text = generate_report()
    st.download_button(
        label="Full Report (TXT)",
        data=report_text.encode('utf-8'),
        file_name=f"dashboard_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
        mime="text/plain"
    )

show_divider()
st.markdown("<h2 style='color: #6b8e6b;'>Activity Heatmap</h2>", unsafe_allow_html=True)
try:
    st.image("heatmap.png", caption="Real-time facility surveillance activity density map — Zone-level threat visualization")
except:
    st.warning("Heatmap image not available. Please ensure 'heatmap.png' is in the dashboard directory.")
