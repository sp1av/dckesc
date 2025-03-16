import uuid

class Config:
    SQLALCHEMY_BINDS = {
        'dckesc': 'postgresql://xk3TbFu0ZC7HMfpZ4Bnjv8UXgJP:DMKO6a76mNYj0LHYukfbWMvn0qR@postgres:5432/dckesc',
        'web': "postgresql://xk3TbFu0ZC7HMfpZ4Bnjv8UXgJP:DMKO6a76mNYj0LHYukfbWMvn0qR@postgres:5432/web"
    }
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = str(uuid.uuid4())
