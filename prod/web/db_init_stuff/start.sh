#!/bin/bash
echo "healthcheck start"


PGPASSWORD="DMKO6a76mNYj0LHYukfbWMvn0qR" psql -U "xk3TbFu0ZC7HMfpZ4Bnjv8UXgJP" -d postgres -h postgres -f /app/db_init_stuff/init.sql

PGPASSWORD="DMKO6a76mNYj0LHYukfbWMvn0qR" psql -U "xk3TbFu0ZC7HMfpZ4Bnjv8UXgJP" -d web -h postgres -c "SELECT 1 FROM users LIMIT 1;" > /dev/null 2>&1

if [ $? -eq 0 ]; then
  echo "Database and tables are initialized!"
  echo 'READY=0' | tee -a /etc/environment
  source /etc/environment
  exit 0
else
  echo "Database is not ready..."
  exit 1
fi
