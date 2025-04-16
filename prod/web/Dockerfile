FROM debian:latest

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    postgresql-client

RUN groupadd -r web-app && useradd -r -g web-app -s /bin/bash web-app

RUN pip install flask \
	flask_sqlalchemy \
	flask_bcrypt \
	flask_login \
	requests \
	gunicorn \
	argon2-cffi \
	psycopg2-binary \ 
	reportlab --break-system-packages

	
WORKDIR /app
COPY . .

# Set ownership and permissions
RUN chown -R web-app:web-app /app && \
    chmod +x /app/db_init_stuff/start.sh && \
    chmod 755 /app

EXPOSE 1703

# Switch to web-app user
USER web-app

CMD ["python3", "app.py"]
#CMD ["gunicorn", "--bind", "0.0.0.0:1703", "app:app"]