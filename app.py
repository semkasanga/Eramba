import subprocess
import ipaddress
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/ping', methods=['GET'])
def ping():
    user_ip = request.args.get('ip', '')
    # --- SCÉNARIO DE PROTECTION : VALIDATION STRICTE ---
    try:
        ipaddress.ip_address(user_ip)
    except ValueError:
        return jsonify({"error": "Attaque détectée ou IP invalide ! Saisie refusée."}), 400
    
    res = subprocess.run(["ping", "-c", "1", user_ip], capture_output=True, text=True)
    return res.stdout

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
