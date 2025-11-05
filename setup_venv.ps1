# Create and activate virtual environment
python -m venv venv
.\venv\Scripts\activate

# Upgrade pip and install requirements
python -m pip install --upgrade pip
pip install -r requirements.txt

Write-Host "Virtual environment setup complete. To activate it, run: .\venv\Scripts\activate"
