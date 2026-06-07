"""
Smart Cybersecurity Assistant - Data Visualization
Generates charts and visualizations for security data
"""

import io
import json
import base64
from datetime import datetime, timedelta
from typing import Dict, List, Optional

import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import plotly.graph_objects as go
import plotly.express as px
from plotly.utils import PlotlyJSONEncoder
import pandas as pd
import numpy as np
from loguru import logger


class SecurityDashboard:
    """
    Generates security visualizations for the web dashboard
    """

    @staticmethod
    def create_threat_timeline(threats: List[Dict]) -> str:
        """
        Create threat detection timeline chart
        Returns: Plotly JSON string
        """
        if not threats:
            threats = SecurityDashboard._generate_demo_threats()

        df = pd.DataFrame(threats)
        df['timestamp'] = pd.to_datetime(df['timestamp'])

        # Color mapping
        color_map = {
            "CRITICAL": "#FF0000",
            "HIGH": "#FF6600",
            "MEDIUM": "#FFAA00",
            "LOW": "#00AA00",
            "INFO": "#0066FF",
        }

        fig = px.scatter(
            df,
            x='timestamp',
            y='threat_type',
            color='severity',
            color_discrete_map=color_map,
            size=[15] * len(df),
            hover_data=['description', 'source_ip'],
            title="🛡️ Threat Detection Timeline",
            labels={'timestamp': 'Time', 'threat_type': 'Threat Type'},
        )

        fig.update_layout(
            template="plotly_dark",
            paper_bgcolor="#1a1a2e",
            plot_bgcolor="#16213e",
            font=dict(color="#e0e0e0"),
            height=400,
        )

        return json.dumps(fig, cls=PlotlyJSONEncoder)

    @staticmethod
    def create_ip_heatmap(ip_data: Dict[str, int]) -> str:
        """
        Create attack frequency heatmap by IP
        """
        if not ip_data:
            ip_data = {
                "192.168.1.100": 45,
                "10.0.0.50": 32,
                "172.16.0.1": 18,
                "45.33.32.156": 87,
                "8.8.8.8": 5,
            }

        ips = list(ip_data.keys())[:15]
        counts = [ip_data[ip] for ip in ips]

        colors = ['#FF0000' if c > 50 else '#FF6600' if c > 20 else '#FFAA00'
                 for c in counts]

        fig = go.Figure(go.Bar(
            x=counts,
            y=ips,
            orientation='h',
            marker_color=colors,
            text=counts,
            textposition='outside',
        ))

        fig.update_layout(
            title="🌐 Attack Frequency by Source IP",
            xaxis_title="Number of Attempts",
            yaxis_title="Source IP",
            template="plotly_dark",
            paper_bgcolor="#1a1a2e",
            plot_bgcolor="#16213e",
            font=dict(color="#e0e0e0"),
            height=400,
        )

        return json.dumps(fig, cls=PlotlyJSONEncoder)

    @staticmethod
    def create_threat_severity_pie(severity_counts: Dict[str, int]) -> str:
        """Create pie chart of threats by severity"""
        if not severity_counts:
            severity_counts = {
                "CRITICAL": 5,
                "HIGH": 12,
                "MEDIUM": 28,
                "LOW": 45,
                "INFO": 10,
            }

        colors = ['#FF0000', '#FF6600', '#FFAA00', '#00AA00', '#0066FF']

        fig = go.Figure(data=[go.Pie(
            labels=list(severity_counts.keys()),
            values=list(severity_counts.values()),
            hole=0.4,
            marker_colors=colors,
        )])

        fig.update_layout(
            title="📊 Threats by Severity",
            template="plotly_dark",
            paper_bgcolor="#1a1a2e",
            font=dict(color="#e0e0e0"),
            height=350,
        )

        return json.dumps(fig, cls=PlotlyJSONEncoder)

    @staticmethod
    def create_network_activity_graph(hourly_data: List[int]) -> str:
        """Create network activity over time"""
        hours = list(range(24))
        if not hourly_data:
            np.random.seed(42)
            hourly_data = (np.random.poisson(20, 24) +
                          np.sin(np.linspace(0, 2*np.pi, 24)) * 10).tolist()

        fig = go.Figure()

        # Normal traffic
        fig.add_trace(go.Scatter(
            x=hours,
            y=hourly_data,
            mode='lines+markers',
            name='Network Activity',
            line=dict(color='#00FFFF', width=2),
            fill='tozeroy',
            fillcolor='rgba(0, 255, 255, 0.1)',
        ))

        # Threshold line
        threshold = max(hourly_data) * 0.7
        fig.add_hline(
            y=threshold,
            line_dash="dash",
            line_color="red",
            annotation_text="Alert Threshold",
        )

        fig.update_layout(
            title="📈 Network Activity (24h)",
            xaxis_title="Hour of Day",
            yaxis_title="Connections",
            template="plotly_dark",
            paper_bgcolor="#1a1a2e",
            plot_bgcolor="#16213e",
            font=dict(color="#e0e0e0"),
            height=350,
        )

        return json.dumps(fig, cls=PlotlyJSONEncoder)

    @staticmethod
    def _generate_demo_threats() -> List[Dict]:
        """Generate demo threats for visualization"""
        import random
        threat_types = ["BRUTE_FORCE", "PORT_SCAN", "SQL_INJECTION",
                       "XSS_ATTEMPT", "SUSPICIOUS_PROCESS"]
        severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

        threats = []
        base_time = datetime.now() - timedelta(hours=24)

        for i in range(50):
            t = base_time + timedelta(hours=random.uniform(0, 24))
            threats.append({
                "id": f"THREAT-{i}",
                "threat_type": random.choice(threat_types),
                "severity": random.choice(severities),
                "description": "Demo threat for visualization",
                "source_ip": f"192.168.{random.randint(1,5)}.{random.randint(1,255)}",
                "timestamp": t.isoformat(),
            })

        return threats