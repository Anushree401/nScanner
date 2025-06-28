from flask import Flask, render_template, redirect, url_for, request
import requests
import json 
from scanner import PassiveScanner, ActiveScanner
import subprocess
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per minute"]
)

@app.route('/', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def index():
    result = []
    recon = {}

    if request.method == 'POST':
        target = request.form.get('target')
        ports = request.form.get('ports')
        verbose = request.form.get('verbose') == 'on'
        scan_type = request.form.get('scan')

        active = ActiveScanner()
        passive = PassiveScanner()

        if target:
            if scan_type == 'active':
                try:
                    result = active.scan(target, ports, verbose)
                except Exception as e:
                    result = [f"[!] Error during active scan: {str(e)}"]
            elif scan_type == 'passive':
                try:
                    recon = passive.full_recon(target)
                except Exception as e:
                    recon = {"error": f"[!] Error during passive recon: {str(e)}"}

    return render_template("scanner_index.html", result=result, recon=recon)

@app.route("/about")
def about():
    return render_template("about.html")

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000)  