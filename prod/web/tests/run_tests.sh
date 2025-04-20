#!/bin/bash

# Activate virtual environment if it exists
if [ -d "venv" ]; then
    source venv/bin/activate
fi

# Install test requirements
pip install -r requirements-test.txt

# Run tests with coverage
pytest --cov=app --cov-report=term-missing tests/

# Generate HTML coverage report
pytest --cov=app --cov-report=html tests/

# Deactivate virtual environment if it was activated
if [ -d "venv" ]; then
    deactivate
fi 