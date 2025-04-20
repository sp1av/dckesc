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
VALUES ('admin', '$2b$12$DLyCejKTO4mQZv.h1pD9Ju9p.jf439lwR.Wbz2MNt/134P.wkGkDK', 'admin')
ON CONFLICT (username) DO NOTHING;
