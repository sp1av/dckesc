import uuid, os

class Config:
    user = os.getenv("DB_USERNAME")
    password = os.getenv("DB_PASSWORD")
    SQLALCHEMY_BINDS = {
        'dckesc': f"postgresql://{user}:{password}@postgres:5432/dckesc",
        'web': f"postgresql://{user}:{password}@postgres:5432/web"
    }
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = str(uuid.uuid4())

class Variables:
    HOST = "192.168.0.164"
