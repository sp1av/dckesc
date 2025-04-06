import os

class Config:
    user = os.getenv("DB_USERNAME")
    os.unsetenv("DB_USERNAME")
    password = os.getenv("DB_PASSWORD")
    os.unsetenv("DB_PASSWORD")
    SQLALCHEMY_BINDS = {
        'dckesc': f"postgresql://{user}:{password}@postgres:5432/dckesc",
        'web': f"postgresql://{user}:{password}@postgres:5432/web"
    }
    SQLALCHEMY_TRACK_MODIFICATIONS = False
