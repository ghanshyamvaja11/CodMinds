#!/bin/bash

echo "Pulling latest code from GitHub..."
git pull origin main

echo "Activating virtual environment..."
source venv/bin/activate

echo "Installing dependencies..."
pip install -r requirements.txt

echo "Applying database migrations..."
python manage.py migrate

echo "Collecting static files..."
python manage.py collectstatic --noinput

echo "Restarting Gunicorn..."
sudo systemctl restart gunicorn

echo "Restarting Nginx..."
sudo systemctl restart nginx

echo "Deployment completed successfully!"