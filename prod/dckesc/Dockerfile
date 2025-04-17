FROM debian:latest

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    openssh-server \
    libcap2-bin \
    curl \
    supervisor

# Create web-app user and group with home directory
RUN groupadd -r web-app && useradd -r -g web-app -s /bin/bash -m -d /home/web-app web-app

RUN pip install flask \
	flask_sqlalchemy \
	requests \
	pwntools \
	psycopg2-binary --break-system-packages \
	gunicorn


RUN curl -sfL https://github.com/aquasecurity/trivy/releases/download/v0.61.0/trivy_0.61.0_Linux-64bit.deb -o /tmp/trivy.deb
RUN dpkg -i /tmp/trivy.deb

RUN useradd -m -s /bin/bash stuff

RUN mkdir -p /var/run/sshd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config && \
    echo 'AllowUsers stuff' >> /etc/ssh/sshd_config && \
    echo 'Match User stuff' >> /etc/ssh/sshd_config && \
    echo '    PermitOpen localhost:*' >> /etc/ssh/sshd_config && \
    echo '    ForceCommand /usr/sbin/nologin' >> /etc/ssh/sshd_config && \
    echo '    AllowTcpForwarding remote' >> /etc/ssh/sshd_config && \
    echo '    PermitTTY no' >> /etc/ssh/sshd_config

USER stuff
RUN mkdir -p /home/stuff/.ssh
RUN echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPiaaaVgDOdLEOiCNmNRkf2NR0VftRWRtCaqTBNhBNco alkar@darloki" > /home/stuff/.ssh/authorized_keys && \
    chmod 600 /home/stuff/.ssh/authorized_keys; \
    chmod 700 /home/stuff/.ssh

USER root

WORKDIR /dckesc
COPY . .

RUN chown -R web-app:web-app /dckesc && \
    chmod 755 /dckesc && \
    chown -R web-app:web-app /home/web-app && \
    chmod 700 /home/web-app

COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf
RUN chmod 644 /etc/supervisor/conf.d/supervisord.conf

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
