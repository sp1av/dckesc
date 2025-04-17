from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
import psycopg2
import os
import requests
from sqlalchemy import nullsfirst
import multiprocessing
import threading
import importlib
import json
import pwn
import time
from sqlalchemy.dialects.postgresql import JSONB
from datetime import datetime
import subprocess

from config import Config

config = {}
config["modules"] = {}

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)


class Docker(db.Model):
    __bind_key__ = 'dckesc'

    id = db.Column(db.Integer, primary_key=True)
    docker_id = db.Column(db.String(20)) # docker container id
    scan_id = db.Column(db.Integer, nullable=False) # id of scan
    os = db.Column(db.String(20)) # os in docker
    port = db.Column(db.Integer, nullable=False) # port for this scan
    state = db.Column(db.String(20), nullable=False)
    inspect = db.Column(JSONB) # row for docker inspect output
    vulnerabilities = db.Column(JSONB)


class Scans(db.Model):
    __bind_key__ = 'dckesc'

    id = db.Column(db.Integer, primary_key=True) #scan id
    uuid = db.Column(db.String(40), nullable=False, unique=True) # uuid.uuid4() - len=38 - for control
    name = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(10), nullable=False) # Recurring/One-time
    mode = db.Column(db.String(20), nullable=False) # offensive/defensive
    date = db.Column(db.String(20), nullable=False) # "2001-70-30 16:13:00"
    state = db.Column(db.String(20), nullable=False) # pending/ongoing/finished
    password = db.Column(db.String(40), nullable=False, unique=True)


class ImageScans(db.Model):
    __bind_key__ = 'dckesc'

    id = db.Column(db.Integer, primary_key=True) #scan id
    uuid = db.Column(db.String(40), nullable=False, unique=True) # uuid.uuid4() - len=38 - for registry
    image_name = db.Column(db.String(20), nullable=False) # image name
    registry = db.Column(db.String(20), nullable=False)  # image registry
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)
    scan_data = db.Column(db.JSON) # full image report
    username = db.Column(db.String(100), nullable=False)


class Ports(db.Model):
    __bind_key__ = 'dckesc'

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, nullable=False)
    port = db.Column(db.Integer, unique=True, nullable=False)


def control(read_til, server, cmd):
    server.sendline((cmd).encode("utf-8"))
    ans = server.recvuntil(read_til.encode('utf-8')).decode('utf-8')
    ans = ans.replace(cmd, '')
    ans = ans.replace(read_til, '').strip()
    return ans


def parse_modules():
    modules_dir = "modules"
    global config

    def process_config(data):
        global config
        module_name = data.get("module_name")
        data_from_main = data.get("data_from_main")


        config["modules"][module_name] = {
            "name": module_name,
            "data_from_main": data_from_main
        }

    def process_module(module_path):
        config_path = os.path.join(module_path, 'config.json')
        with open(config_path, 'r') as config_file:
            config_data = json.load(config_file)
            process_config(config_data)

    for root, dirs, files in os.walk(modules_dir):
        for dir_name in dirs:
            module_path = os.path.join(root, dir_name)
            if "__pycache__" not in module_path:
                process_module(module_path)




def proceed_target(data):
    def worker(target_port, id, password):
        conn = pwn.remote("127.0.0.1", target_port)
        conn.settimeout(10)
        conn.recv(17)
        conn.sendline(password.encode("utf-8"))
        conn.recvline()
        conn.sendline(b" ")
        conn.recvline() # this is the problem
        read_til = (conn.recvuntil(b":/").decode('utf-8') + conn.recv(1).decode('utf-8'))
        conn.recvuntil(read_til.encode('utf-8')).decode('utf-8')
        ans = load_module("basic_checks", read_til, conn)
        data = {"result": str(ans)}
        requests.post(f"http://127.0.0.1:2517/api/update/{id}", data=data)


    def load_module(module_name, read_til, conn):
        module_path = f"modules/{module_name}/script.py"
        spec = importlib.util.spec_from_file_location(module_name, module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        data = {}
        for name, obj in globals().items():
            if name in config["modules"][module_name]["data_from_main"]:
                data[name] = obj

        for name, obj in locals().items():
            if name in config["modules"][module_name]["data_from_main"]:
                data[name] = obj

        ans = module.main(data)
        return ans


    for attack in data:
        port, id, password = attack["port"], attack["id"], attack["password"]
        process = multiprocessing.Process(target=worker, args=(port, id, password))
        process.start()





@app.route('/api/update/<int:id>', methods=["POST"])
def update(id):
    data = request.form['result']
    if request.method == 'POST':
        docker = Docker.query.filter_by(id=id).first()
        if docker:
            docker.vulnerabilities = data
            scan_id = docker.scan_id
            scan = Scans.query.filter_by(id=scan_id).first()
            docker.state = "finished"
            db.session.commit()
            if scan.mode == "offensive":
                scan.state = "finished"
                port = Ports.query.filter_by(port=docker.port).first()
            else:
                target = Docker.query.filter_by(scan_id=id).all()
                cnt = 0
                for container in target:
                    if container.state == "finished":
                        cnt += 1
                if cnt == len(target):
                    if scan.status == "one-time":
                        scan.state = "finished"
                        port = Ports.query.filter_by(port=docker.port).first()
                    elif scan.status == "recurring":
                        scan.state = "pending"
                    db.session.commit()
            return "Updated successfully", 200
        else:
            return "Docker entry not found", 404


@app.route('/api/start', methods=["POST"])
def start():
    uuid = request.form['scan_uuid']
    id = request.form['scan_id']
    if not Scans.query.filter_by(id=id, uuid=uuid).first():
        return "Error"


    myscan = Scans.query.filter_by(id=id, uuid=uuid).first()
    name, mode, data = myscan.name, myscan.mode, []
    print(f"Proceeding of {name} scan starts")
    target = Docker.query.filter_by(scan_id=id).all()

    for dockers in target:
        target_info = {
            "port": dockers.port,
            "id": dockers.id,
            "password": myscan.password
        }
        data.append(target_info)
        if dockers.state == "pending":
            dockers.state = "ongoing"

    db.session.commit()
    #process = multiprocessing.Process(target=proceed_target, args=(data, mode, id))
    #process.start()
    proceed_target(data)
    if myscan.state == "pending":
        myscan.state = "ongoing"
        db.session.commit()

    return "Scanning started"





@app.route("/api/image/scan", methods=["POST"])
def image_scan():
    def clean_trivy_output(data):
        keep_keys = [
            "Title",
            "VulnerabilityID",
            "PkgID",
            "PkgName",
            "PkgIdentifier",
            "InstalledVersion",
            "Severity",
            "Description",
            "PrimaryURL",
            "References",
            "CVSS"
        ]

        for result in data.get("Results", []):
            if "Vulnerabilities" in result:
                for vulnerability in result["Vulnerabilities"]:
                    vulnerability_keys = {key: value for key, value in vulnerability.items() if key in keep_keys}
                    
                    if "CVSS" in vulnerability_keys:
                        cvss_data = vulnerability_keys["CVSS"]
                        if "nvd" in cvss_data:
                            vulnerability_keys["CVSS"] = {
                                "nvd": {
                                    "V3Score": cvss_data["nvd"].get("V3Score")
                                }
                            }
                    vulnerability.clear()
                    vulnerability.update(vulnerability_keys)
        return data

    try:
        try:
            image = request.form["image"]
            registry = request.form["registry"]
            uuid = request.form["uuid"]
            username = request.form["username"]
            username = str(os.getenv("REGISTRY_USERNAME"))
            password = str(os.getenv("REGISTRY_PASSWORD"))
        except Exception as e:
            print("request form error")
            return jsonify({"error": str(e)}), 400

        cmd = [
            "trivy",
            "--insecure",
            "--image-src", "remote",
            "image",
            "--format", "json",
            f"{registry}/{image}",
            "--username", username,
            "--password", password
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
        except Exception as e:
            print("subprocess error")
            return jsonify({"error": str(e)}), 500
        
        if result.returncode != 0:
            return jsonify({"error": f"Trivy scan failed: {result.stderr}"}), 500
        try:
            scan_data = json.loads(result.stdout)
            cleaned_data = scan_data
        except Exception as e:
            print("json error")
            return jsonify({"error": str(e)}), 500
        try:
            scan = ImageScans(
                image_name=image,
                registry=registry,
                scan_data=cleaned_data,
                uuid=uuid,
                username=username
            )
            db.session.add(scan)
            db.session.commit()
        except Exception as e:
            print("db error")
            return jsonify({"error": str(e)}), 500

        return jsonify({"message": "Scan completed successfully", "uuid": uuid}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500





if __name__ == '__main__':
    parse_modules()
    with app.app_context():
        db.create_all(bind_key='dckesc')
        db.create_all(bind_key='web')
    app.run(debug=False, port=2517, host="0.0.0.0")
