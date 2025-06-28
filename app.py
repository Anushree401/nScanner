from flask import Flask, render_template, redirect, url_for, request, limiter
import requests
import json 
from scanner import PassiveScanner, ActiveScanner
import subprocess

app = Flask(__name__)

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


if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=80)  