FROM debian:latest

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    postgresql-client

RUN groupadd -r webapp && useradd -r -g webapp -s /bin/bash webapp

RUN pip install flask \
	flask_sqlalchemy \
	flask_bcrypt \
	flask_login \
	requests \
	gunicorn \
	argon2-cffi \
	psycopg2-binary \ 
	PyYAML \
	reportlab --break-system-packages

	
WORKDIR /app
COPY . .

RUN chown -R webapp:webapp /app && \
    chmod +x /app/db_init_stuff/start.sh && \
    chmod 755 /app

EXPOSE 1703

USER webapp

CMD ["python3", "app.py"]
#CMD ["gunicorn", "--bind", "0.0.0.0:1703", "app:app"]