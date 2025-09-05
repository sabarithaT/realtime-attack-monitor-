import pandas as pd
from scapy.all import sniff, IP, TCP
from datetime import datetime
from threading import Thread
from dash import Dash, dcc, html
from dash.dependencies import Output, Input
import plotly.express as px

# ----------------------------
# Data storage
# ----------------------------
columns = ["timestamp", "src_ip", "dst_port", "alert_type"]
attack_log = pd.DataFrame(columns=columns)

# ----------------------------
# Detection function
# ----------------------------
def detect_attack(pkt):
    global attack_log
    if IP in pkt:
        src_ip = pkt[IP].src
        dst_port = pkt[TCP].dport if TCP in pkt else None
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Port scanning detection: multiple ports accessed from same IP quickly
        recent = attack_log[attack_log['src_ip'] == src_ip]
        recent_ports = recent['dst_port'].tolist()
        if dst_port and dst_port not in recent_ports:
            alert_type = "Port Scan"
            attack_log = pd.concat([attack_log, pd.DataFrame([{
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_port": dst_port,
                "alert_type": alert_type
            }])], ignore_index=True)
            print(f"[ALERT] {alert_type} from {src_ip} on port {dst_port}")

# ----------------------------
# Packet capture in background
# ----------------------------
def packet_sniffer():
    sniff(prn=detect_attack, filter="tcp", store=False)

# ----------------------------
# Dash Dashboard
# ----------------------------
app = Dash(__name__)
app.layout = html.Div([
    html.H2("Real-Time Attack Dashboard"),
    dcc.Graph(id="live-line-chart"),
    html.H4("Detected Attacks Log"),
    dcc.Interval(id="interval-component", interval=2000, n_intervals=0),
    html.Div(id="attack-table")
])

@app.callback(
    Output("live-line-chart", "figure"),
    Output("attack-table", "children"),
    Input("interval-component", "n_intervals")
)
def update_dashboard(n):
    global attack_log
    if attack_log.empty:
        fig = px.line(pd.DataFrame({"timestamp": [], "count": []}), x="timestamp", y="count")
        table_html = "No attacks detected yet."
        return fig, table_html
    
    # Line chart: attack counts over time
    attack_count = attack_log.groupby("timestamp").size().reset_index(name="count")
    fig = px.line(attack_count, x="timestamp", y="count", title="Attacks Over Time")
    
    # Table: last 10 attacks
    last_attacks = attack_log.tail(10)
    table_html = html.Table([
        html.Thead(html.Tr([html.Th(col) for col in last_attacks.columns])),
        html.Tbody([
            html.Tr([html.Td(last_attacks.iloc[i][col]) for col in last_attacks.columns])
            for i in range(len(last_attacks))
        ])
    ])
    
    return fig, table_html

# ----------------------------
# Run sniffer in background thread
# ----------------------------
sniffer_thread = Thread(target=packet_sniffer, daemon=True)
sniffer_thread.start()

# ----------------------------
# Run dashboard
# ----------------------------
if __name__ == "__main__":
    app.run(debug=True)
