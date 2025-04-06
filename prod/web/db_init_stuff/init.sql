CREATE DATABASE web;
CREATE DATABASE dckesc;

\c web;

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role VARCHAR(50) NOT NULL
);

INSERT INTO users (username, password, role)
VALUES ('splav', '$2b$12$bYLZnYdH.vXr/jeRt38jU.s3uDu3oBqL9rOrhRcQXFuplRpPE0Yby', 'admin')
ON CONFLICT (username) DO NOTHING;
