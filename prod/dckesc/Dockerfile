FROM debian:latest

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    openssh-server \
    libcap2-bin


RUN pip install flask \
	flask_sqlalchemy \
	requests \
	pwntools \
	psycopg2-binary --break-system-packages


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

CMD ["python3", "/dckesc/dckesc.py"]
