#!/bin/bash
set -e

echo "Setting up python virtual environment."
if [ ! -f "venv/bin/activate" ]; then
    python3 -m venv "venv"
    source venv/bin/activate
    pip install --disable-pip-version-check -q -r requirements.txt
fi
source venv/bin/activate

echo "Running test."
python test.py
