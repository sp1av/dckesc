import os
import time
import json
import io
import uuid
import socket
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from flask import Flask, request, send_file
from functools import wraps
from flask import abort
from argon2 import PasswordHasher
from flask_login import current_user
from flask import send_from_directory
import requests
from sqlalchemy.dialects.postgresql import JSONB
from config import Config
from config import Variables
import sys
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

app = Flask(__name__)
HOST = Variables.HOST

app.config.from_object(Config)

ph = PasswordHasher()
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.session_protection = "strong"

class Users(UserMixin, db.Model):
    __bind_key__ = "web"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    role = db.Column(db.String(10), nullable=False)
    password = db.Column(db.String(255), nullable=False)


class AvailableScans(db.Model):
    __bind_key__ = 'web'

    id = db.Column(db.Integer, primary_key=True)
    available_scan = db.Column(db.Integer, nullable=False)
    username = db.Column(db.String(100), nullable=False)


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
    image_name = db.Column(db.String(40), nullable=False) # image name
    registry = db.Column(db.String(20), nullable=False)  # image registry
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)
    scan_data = db.Column(db.JSON) # full image report
    username = db.Column(db.String(100), nullable=False)
    uuid = db.Column(db.String(40), nullable=True, unique=True) # uuid.uuid4() - len=38 - for registry

class Docker(db.Model):
    __bind_key__ = 'dckesc'

    id = db.Column(db.Integer, primary_key=True)
    docker_id = db.Column(db.String(20)) # docker container id
    scan_id = db.Column(db.Integer, nullable=False) # id of scan
    os = db.Column(db.String(20)) # os in docker
    port = db.Column(db.Integer, nullable=False) # port for this scan
    state = db.Column(db.String(20), nullable=False) # pending/ongoing/finished
    inspect = db.Column(JSONB) # row for docker inspect output
    vulnerabilities = db.Column(JSONB)


class Ports(db.Model):
    __bind_key__ = 'dckesc'

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, nullable=False)
    port = db.Column(db.Integer, unique=True, nullable=False)


def role_required(role):
    def decorator(func):
        @wraps(func)
        def wrapped_view(*args, **kwargs):
            if not current_user.is_authenticated:
                return abort(401)
            if current_user.role != role:
                return abort(403)
            return func(*args, **kwargs)

        return wrapped_view

    return decorator


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

@app.route('/')
@login_required
def index():
    try:
        # Get scan statistics
        total_scans = Scans.query.count() + ImageScans.query.count()
        total_containers = ImageScans.query.count()
        
        # Get recent scans (last 5)
        recent_scans = Scans.query.order_by(Scans.date.desc()).limit(5).all()
        
        # Get vulnerability statistics from image scans
        critical_vulns = 0
        high_vulns = 0
        medium_vulns = 0
        low_vulns = 0
        
        image_scans = ImageScans.query.all()
        for scan in image_scans:
            if scan.scan_data and isinstance(scan.scan_data, dict):
                for result in scan.scan_data.get('Results', []):
                    for vuln in result.get('Vulnerabilities', []):
                        severity = vuln.get('Severity', '').upper()
                        if severity == 'CRITICAL':
                            critical_vulns += 1
                        elif severity == 'HIGH':
                            high_vulns += 1
                        elif severity == 'MEDIUM':
                            medium_vulns += 1
                        elif severity == 'LOW':
                            low_vulns += 1
        
        return render_template("main.html", total_scans=total_scans, total_containers=total_containers, recent_scans=recent_scans, critical_vulns=critical_vulns, high_vulns=high_vulns, medium_vulns=medium_vulns, low_vulns=low_vulns)
    except Exception as e:
        print(e)
        return render_template("main.html", total_scans=0, total_containers=0, recent_scans=[], critical_vulns=0, high_vulns=0, medium_vulns=0, low_vulns=0)

@app.route('/about')
def about():
    return render_template("about.html")

@app.route('/admin/add_user', methods=['GET', 'POST'])
@login_required
@role_required("admin")
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        user_exists = Users.query.filter_by(username=username).first()
        if user_exists:
            flash("Username already exists!", "danger")
            return redirect(url_for('register'))
        if role not in ['user', 'admin']:
            flash("Invalid role", "danger")
            return redirect(url_for('/admin/add_user'))
        new_user = Users(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()

        flash("User added successfully!", "success")
        return redirect(url_for('login'))

    return render_template('add_user.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = Users.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for('index'))
        else:
            flash("Invalid username or password", "danger")
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out", "info")
    return redirect(url_for('login'))


@app.route('/view', methods=['GET'])
@login_required
def view_scans():
    available_scans = AvailableScans.query.filter_by(username=current_user.username).all()
    scan_ids = [scan.available_scan for scan in available_scans]
    scans = Scans.query.filter(Scans.id.in_(scan_ids)).all()
    return render_template('view.html', scans=scans)



@app.route('/api/ready', methods=['POST'])
def api_ready():
    if request.method == "POST":
        try:
            uuid = str(request.form.get('uuid', ''))
            id = str(request.form.get('scan_id', ''))
            
            if not uuid or not id:
                return "Missing required parameters", 400
                
            test_1 = Scans.query.filter_by(id=int(id)).first()
            test_2 = Scans.query.filter_by(uuid=uuid).first()
            if not test_1 or not test_2:
                return "Invalid scan ID or UUID", 404
                
            data = {
                "scan_uuid": uuid,
                "scan_id": id
            }
            
            try:
                alarm = requests.Session()
                response = alarm.post("http://dckesc:2517/api/start", data=data)
                response.raise_for_status()
                return "Scanning started", 200
            except:
                return "Failed to start scanning service", 500
                    
        except Exception as e:
            return "Internal server error", 500
    else:
        return "Method not allowed", 405


@app.route('/static/bin/<file>')
def openssh(file):
    if file in ["openssh", "listener", "docker", "ssh_key", "curl"]:
        return send_from_directory("/app/static/bin", file, as_attachment=True)
    else:
        return "Not allowed"


@app.route('/share', methods=['GET', 'POST'])
@login_required
def share_scan():
    scan_ids = [row.available_scan for row in AvailableScans.query.filter_by(username=current_user.username).all()]

    scans = Scans.query.filter(Scans.id.in_(scan_ids)).all()

    users = Users.query.filter(Users.username != current_user.username).all()

    if request.method == 'POST':
        scan_id = request.form.get('scan_id')
        share_with = request.form.get('username')

        if not scan_id or not share_with:
            flash("Please select both scan and user!", "error")
            return redirect(url_for('share_scan'))

        if not Users.query.filter_by(username=share_with).first():
            flash("This user does not exist!", "error")
            return redirect(url_for('share_scan'))

        existing_share = AvailableScans.query.filter_by(available_scan=scan_id, username=share_with).first()
        if existing_share:
            flash("This scan is already shared with this user!", "warning")
            return redirect(url_for('share_scan'))

        new_share = AvailableScans(available_scan=scan_id, username=share_with)
        db.session.add(new_share)
        db.session.commit()

        flash(f"You shared scan {scan_id} with {share_with}!", "success")
        return redirect(url_for('view_scans'))

    return render_template('share.html', scans=scans, users=users)


@app.route('/create')
@login_required
def create():
    return render_template('create.html')


@app.route('/settings', methods=['GET'])
@login_required
def settings():
    return render_template("settings.html")

@app.route('/api/create/offensive', methods=['POST'])
@app.route('/api/create/defensive', methods=['POST'])
@login_required
def create_scan():

    def check_port(port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        while True:
            if Ports.query.filter_by(port=port).first():
                port += 1
                continue
            if port == 65535:
                port = 1001
            try:
                sock.bind(('localhost', port))
            except socket.error:
                port += 1
                continue
            else:
                sock.close()
                return port

    try:
        scan_name = request.form.get('scan_name')
        scan_type = request.form.get('scan_type')
        container_ids = request.form.get('container_ids')
        current_datetime = datetime.now().strftime("%Y-%m-%d %H:%M")
        file_content = ""
        if str(scan_type) == "None":
            control_id = str(uuid.uuid4())
            password = str(uuid.uuid4())
            new_scan = Scans(password=password, name=scan_name ,uuid=control_id, date=current_datetime, state="pending", status='one-time', mode="offensive")
            db.session.add(new_scan)
            db.session.commit()

            scan_id = Scans.query.filter_by(uuid=control_id).first().id
            user = current_user.username
            scan_for_look = AvailableScans(available_scan=scan_id, username=user)
            db.session.add(scan_for_look)
            db.session.commit()

            port = check_port(1000)
            port_taken = Ports(scan_id=scan_id, port=port)
            db.session.add(port_taken)
            db.session.commit()

            docker_scan_part = Docker(docker_id='1', scan_id=scan_id, port=port, state='pending')
            db.session.add(docker_scan_part)
            db.session.commit()
            with open("/app/stuff_scripts/offensive.sh", "r") as file:
                file_content = file.read()

            file_content = file_content.replace("$PORT_SPLAV", str(port))
            file_content = file_content.replace("$HOSTIP_SPLAV", str(HOST))
            file_content = file_content.replace("$SCAN_ID_SPLAV", str(scan_id))
            file_content = file_content.replace("$CONTROL_SPLAV", str(control_id))
            file_content = file_content.replace("$SPLAVHASH", ph.hash(password))
        else:
            if scan_type == 'one-time' or scan_type == "recurring":
                container_ids = json.loads(container_ids)
                ports = list()
                control_id = str(uuid.uuid4())
                password = str(uuid.uuid4())
                new_scan = Scans(password=password, name=scan_name, uuid=control_id, date=current_datetime, state="pending", status=scan_type, mode="defensive")
                db.session.add(new_scan)
                db.session.commit()
                scan_id = Scans.query.filter_by(uuid=control_id).first().id
                user = current_user.username
                scan_for_look = AvailableScans(available_scan=scan_id, username=user)
                db.session.add(scan_for_look)
                db.session.commit()
                for docker_hostname in container_ids:
                    port = check_port(1000)
                    ports.append(str(port))
                    port_taken = Ports(scan_id=scan_id, port=port)
                    db.session.add(port_taken)
                    db.session.commit()
                    docker_scan_part = Docker(scan_id=scan_id, port=port, state='pending', docker_id=docker_hostname)
                    db.session.add(docker_scan_part)
                    db.session.commit()

                with open("/app/stuff_scripts/defense.sh","r") as file:
                    file_content = file.read()

                ready_ports = " ".join(ports)
                ready_ids = " ".join(container_ids)
                file_content = file_content.replace("$LISTCONTAINERS_SPLAV", str(ready_ids))
                file_content = file_content.replace("$LISTPORTS_SPLAV", str(ready_ports))
                file_content = file_content.replace("$HOSTIP_SPLAV", str(HOST))
                file_content = file_content.replace("$SCAN_ID_SPLAV", str(scan_id))
                file_content = file_content.replace("$CONTROL_SPLAV", str(control_id))
                file_content = file_content.replace("$SPLAVHASH", ph.hash(password))
        file_buffer = io.BytesIO()
        file_buffer.write(file_content.encode('utf-8'))
        file_buffer.seek(0)

        return send_file(file_buffer, as_attachment=True, download_name="agent.sh", mimetype="text/plain")

    except Exception:
        return "Something went bad"


@app.route('/send_data/<docker_id>', methods=["POST"])
def inspect(docker_id):
    if request.method == 'POST':
        try:
            uuid = request.form.get('uuid')
            scan_id = request.form.get('scan_id')
            data_str = request.form.get("data")
            
            if not all([uuid, scan_id, data_str]):
                return "Missing required parameters", 400
                
            data = json.loads(data_str)
            scan = Scans.query.filter_by(id=scan_id, uuid=uuid).first()
            if not scan:
                return "Scan not found", 404
                
            docker = Docker.query.filter_by(scan_id=scan_id, docker_id=docker_id).first()
            if not docker:
                return "Docker entry not found", 404
            
            docker.inspect = data
            db.session.commit()
            return "Updated successfully", 200
  
        except:
            return "Internal server error", 500
    else:
        return "Method not allowed", 405



@app.route('/api/scan/image', methods=["POST"])
@login_required
def proceed_image():
    if request.method == "POST":
        image = request.form.get("image")
        registry = request.form.get("registry")
        uuid = request.form.get("uuid")
        data = {
            "image": image,
            "registry": registry,
            "uuid": uuid
        }
        requests.post("http://dckesc:2517/scan/image", data=data)
    else:
        return "Method not allowed", 405


#@app.route('/scan/<scan_id>/<docker_id>')
#@login_required
#def scan_vulnerabilities(scan_id, docker_id):
#    try:
#        if AvailableScans.query.filter_by(available_scan=scan_id, username=current_user.username).first():
#            try:
#                results = Docker.query.filter_by(scan_id=scan_id).all()
#                docker = results[int(docker_id)]
#                vulnerabilities = docker.vulnerabilities
#                vulnerabilities = vulnerabilities.replace("'", '"').strip()
#                vulnerabilities = vulnerabilities.replace("True", 'true')
#                vulnerabilities = json.loads(vulnerabilities)
#                return render_template('docker_report.html', scan_id=scan_id, id=docker_id, vulnerabilities=vulnerabilities)
#            except Exception as e:
#                return "There is no docker report with this id", 404
#        else:
#            return "Restricted", 403
#    except Exception as e:
#        return "Internal error", 500


@app.route('/scan/<int:scan_id>')
@login_required
def scan_detail(scan_id):
    try:
        if not AvailableScans.query.filter_by(available_scan=scan_id, username=current_user.username).first():
            return "Access denied", 403
            
        try:
            results = Docker.query.filter_by(scan_id=scan_id).all()
            if not results:
                return "No reports found for this scan", 404
                
            multiple_containers = len(results) > 1
            
            scan = Scans.query.filter_by(id=scan_id).first()
            if not scan:
                return "Scan not found", 404
            
            for docker in results:
                if docker.vulnerabilities:
                    if isinstance(docker.vulnerabilities, str):
                        vulnerabilities = docker.vulnerabilities.replace("'", '"').strip()
                        vulnerabilities = vulnerabilities.replace("True", 'true')
                        docker.vulnerabilities = json.loads(vulnerabilities)
                        
            return render_template('report_fin.html', 
                                results=results, 
                                multiple_containers=multiple_containers,
                                scan=scan)
            
        except Exception as e:
            print(e)
            return "Error processing scan data", 500
            
    except Exception as e:
        print(e)
        return "Internal server error", 500


@app.route('/scan/<int:scan_id>/pdf')
@login_required
def generate_pdf_report(scan_id):
    try:
        if not AvailableScans.query.filter_by(available_scan=scan_id, username=current_user.username).first():
            return "Access denied", 403
            
        results = Docker.query.filter_by(scan_id=scan_id).all()
        if not results:
            return "No reports found for this scan", 404
            

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=30)
        styles = getSampleStyleSheet()
        story = []
        
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=16,
            spaceAfter=30,
            alignment=1
        )
        story.append(Paragraph("Docker Security Scan Report", title_style))
        
        scan = Scans.query.filter_by(id=scan_id).first()
        scan_info = [
            ["Scan ID:", str(scan_id)],
            ["Scan Name:", scan.name],
            ["Scan Mode:", scan.mode],
            ["Scan Author:", current_user.username],
            ["Scan Date:", scan.date],
            ["Report Generated:", datetime.now().strftime("%Y-%m-%d %H:%M:%S")]
        ]
        
        scan_table = Table(scan_info, colWidths=[2*inch, 4*inch])
        scan_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(scan_table)
        story.append(Spacer(1, 20))
        
        for docker in results:
            story.append(Paragraph(f"Container {docker.docker_id}", styles['Heading2']))
            
            if docker.vulnerabilities:
                if isinstance(docker.vulnerabilities, str):
                    vulnerabilities = docker.vulnerabilities.replace("'", '"').strip()
                    vulnerabilities = vulnerabilities.replace("True", 'true')
                    vulnerabilities = json.loads(vulnerabilities)
                else:
                    vulnerabilities = docker.vulnerabilities
                    
                for vuln_key, vuln_data in vulnerabilities.items():
                    story.append(Paragraph(f"{vuln_data.get('name', vuln_key)}:", styles['Heading3']))
                    story.append(Paragraph(f"Status: {vuln_data.get('status', 'Unknown')}", styles['Normal']))
                    
                    if 'details' in vuln_data:
                        if isinstance(vuln_data['details'], list):
                            for detail in vuln_data['details']:
                                story.append(Paragraph(f"• {detail}", styles['Normal']))
                        else:
                            story.append(Paragraph(f"Details: {vuln_data['details']}", styles['Normal']))
                    story.append(Spacer(1, 10))
            else:
                story.append(Paragraph("No vulnerabilities found. The container is secure.", styles['Normal']))
            story.append(Spacer(1, 20))
            
        doc.build(story)
        buffer.seek(0)
        
        return send_file(
            buffer,
            as_attachment=True,
            download_name=f"scan_report_{scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
            mimetype='application/pdf'
        )
        
    except Exception as e:
        return "Error generating PDF report", 500


@app.route('/image-scan/view/<int:scan_id>', methods=["GET"])
@login_required
def view_image_scan(scan_id):
    if request.method == "GET":
        try:
            scan = ImageScans.query.filter_by(id=scan_id).first()
            if not scan:
                return "Scan not found", 404
            if scan.username != current_user.username and scan.username != "public":
                return "Access denied", 403

            return render_template('image-scan.html', data=scan.scan_data)

        except Exception as e:
            return "Internal server error", 500
    else:
        return "Method not allowed", 405


@app.route('/image-scan/view')
@login_required
def view_image_scans():
    try:
        scans = ImageScans.query.filter(
            (ImageScans.username == current_user.username) | 
            (ImageScans.username == "public")
        ).order_by(ImageScans.scan_date.desc()).all()
        
        return render_template('image-scans.html', scans=scans)

    except Exception as e:
        flash("Error loading image scans", "error")
        return redirect(url_for('index'))


@app.route('/image-scan/create', methods=['GET', 'POST'])
@login_required
def create_image_scan():
    if request.method == 'POST':
        try:
            images = request.form.getlist('images[]')
            is_public = request.form.get('is_public') == 'on'
            script_mode = request.form.get('script_mode') == 'on'
            
            if not images:
                flash("Please add at least one image", "error")
                return redirect(url_for('create_image_scan'))
            
            if script_mode:
                control_id = str(uuid.uuid4())
                script_content = ""
                
                with open("/app/stuff_scripts/image_scan.sh", "r") as file:
                    script_content = file.read()
                
                script_content = script_content.replace("$HOSTIP_SPLAV", str(HOST))
                script_content = script_content.replace("$CONTROL_SPLAV", str(control_id))
                
                image_list = " ".join(images)
                script_content = script_content.replace("$IMAGES_SPLAV", image_list)
                
                buffer = io.BytesIO()
                buffer.write(script_content.encode('utf-8'))
                buffer.seek(0)
                
                return send_file(
                    buffer,
                    as_attachment=True,
                    download_name="image_scan.sh",
                    mimetype="text/plain"
                )
            else:
                registry = request.form.get('registry')
                tls_verify = request.form.get('tls_verify') == 'on'
                registry_username = request.form.get('registry_username')
                registry_password = request.form.get('registry_password')

                for image in images:
                    scan_uuid = str(uuid.uuid4())
                    
                    data = {
                        "image": image,
                        "registry": registry,
                        "uuid": scan_uuid,
                        "tls_verify": tls_verify
                    }

                    if registry_username and registry_password:
                        data.update({
                            "registry_username": registry_username,
                            "registry_password": registry_password
                        })
                    
                    requests.post("http://dckesc:2517/api/image/scan", data=data)
                
                flash("Image scans started successfully!", "success")
                return redirect(url_for('view_image_scans'))
                
        except Exception as e:
            print(e)
            flash("Error creating image scan", "error")
            return redirect(url_for('create_image_scan'))
            
    return render_template('create-image-scan.html')


@app.route('/api/image-scan/create', methods=['POST'])
def api_image_scan():
    image = request.form["image"]
    registry = request.form["registry"]
    username = request.form["username"]
    password = request.form["password"]
    tls_verify = request.form["tls_verify"]
    data = {
        "image": image,
        "registry": registry,
        "username": username,
        "password": password,
        "tls_verify": tls_verify
    }
    requests.post("http://dckesc:2517//api/image/scan", data=data)
    return "Scan started ", 200

if __name__ == '__main__':

    #with open("/app/db_init_stuff/init.sql", "r") as file:
    #    content = file.read()
    #    hash = bcrypt.generate_password_hash("splav").decode("utf-8")
    #    content = content.replace("HASSSH", hash)
    #with open("/app/db_init_stuff/init.sql", "w") as file:
    #    file.write(content)

    while True:
        if os.system("bash /app/db_init_stuff/start.sh") == 0:
            os.putenv("READY", "0")
            break
        time.sleep(3)
    with app.app_context():
        db.create_all(bind_key='web')
        db.create_all(bind_key='dckesc')

    app.run(port=1703, host="0.0.0.0")
