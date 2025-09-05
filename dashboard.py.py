from flask import Flask, render_template_string
import json
import os

app = Flask(__name__)

LOG_FILE = "logs.json"

@app.route('/')
def dashboard():
    logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            try:
                logs = json.load(f)
            except:
                logs = []
    return render_template_string("""
    <html>
    <head><title>Attack Dashboard</title></head>
    <body>
        <h1>AI Attack Detection Dashboard</h1>
        <table border="1">
            <tr><th>User ID</th><th>Attack Type</th><th>Status</th><th>Timestamp</th></tr>
            {% for log in logs %}
            <tr>
                <td>{{ log.user_id }}</td>
                <td>{{ log.attack }}</td>
                <td>{{ log.status }}</td>
                <td>{{ log.timestamp }}</td>
            </tr>
            {% endfor %}
        </table>
    </body>
    </html>
    """, logs=logs)

if __name__ == '__main__':
    app.run(debug=True)
