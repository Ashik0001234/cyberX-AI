from flask import Flask, render_template, request, redirect, url_for, send_file
import sqlite3
import requests
import base64
from reportlab.pdfgen import canvas

app = Flask(__name__)

# DATABASE

def init_db():

    conn = sqlite3.connect('cyberx.db')

    cursor = conn.cursor()

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS scans(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT,
        result TEXT
    )
    ''')

    conn.commit()

    conn.close()

init_db()

# GET SCANS

def get_scans():

    conn = sqlite3.connect('cyberx.db')

    cursor = conn.cursor()

    cursor.execute(
        "SELECT url, result FROM scans"
    )

    data = cursor.fetchall()

    conn.close()

    return data

# GET COUNTS

def get_counts():

    conn = sqlite3.connect('cyberx.db')

    cursor = conn.cursor()

    cursor.execute(
        "SELECT COUNT(*) FROM scans"
    )

    total = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM scans WHERE result='SAFE'"
    )

    safe = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM scans WHERE result='DANGEROUS'"
    )

    dangerous = cursor.fetchone()[0]

    conn.close()

    return total, safe, dangerous

# LOGIN PAGE

@app.route('/')
def login():

    return render_template(
        'login.html'
    )

# LOGIN CHECK

@app.route('/logincheck', methods=['POST'])
def logincheck():

    username = request.form['username']

    password = request.form['password']

    if username == "admin" and password == "1234":

        return redirect(
            url_for('dashboard')
        )

    else:

        return "Wrong Username or Password"

# DASHBOARD

@app.route('/dashboard')
def dashboard():

    scans = get_scans()

    total, safe, dangerous = get_counts()

    return render_template(
        'index.html',
        scans=scans,
        total=total,
        safe=safe,
        dangerous=dangerous
    )

# REAL VIRUSTOTAL URL CHECK

@app.route('/check', methods=['POST'])
def check():

    url = request.form['url']

    API_KEY = "7d8267439902870a8f91bbc3965a01a2d645d32412dad7223aa32f49f2529307"

    # URL ENCODE

    url_id = base64.urlsafe_b64encode(
        url.encode()
    ).decode().strip("=")

    vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    headers = {

        "x-apikey": API_KEY

    }

    response = requests.get(
        vt_url,
        headers=headers
    )

    data = response.json()

    try:

        malicious = data[
            'data'
        ][
            'attributes'
        ][
            'last_analysis_stats'
        ][
            'malicious'
        ]

    except:

        malicious = 0

    # RESULT

    if malicious > 0:

        result = "DANGEROUS"

        threat_score = "96%"

    else:

        result = "SAFE"

        threat_score = "7%"

    # SAVE DATABASE

    conn = sqlite3.connect('cyberx.db')

    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO scans(url, result) VALUES (?, ?)",
        (url, result)
    )

    conn.commit()

    conn.close()

    scans = get_scans()

    total, safe, dangerous = get_counts()

    return render_template(
        'index.html',
        result=result,
        threat_score=threat_score,
        scans=scans,
        total=total,
        safe=safe,
        dangerous=dangerous
    )

# PDF REPORT

@app.route('/download_report')
def download_report():

    scans = get_scans()

    pdf_file = "CyberX_Report.pdf"

    c = canvas.Canvas(pdf_file)

    c.setFont(
        "Helvetica-Bold",
        18
    )

    c.drawString(
        170,
        800,
        "CyberX AI Security Report"
    )

    c.setFont(
        "Helvetica",
        12
    )

    y = 750

    for scan in scans:

        text = f"URL: {scan[0]} | Result: {scan[1]}"

        c.drawString(
            50,
            y,
            text
        )

        y -= 25

        if y < 50:

            c.showPage()

            y = 800

    c.save()

    return send_file(
        pdf_file,
        as_attachment=True
    )

# RUN APP

if __name__ == '__main__':

    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True
    )