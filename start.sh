#!/bin/bash

echo "======================================"
echo "Cybersecurity Detection Framework"
echo "Module 1: Sensitive Data Detection"
echo "======================================"
echo ""

# Check Python version
python_version=$(python3 --version 2>&1)
echo "✓ Python: $python_version"

# Install dependencies
echo ""
echo "📦 Installing dependencies..."
pip3 install -r requirements.txt

# Initialize database
echo ""
echo "💾 Initializing database..."
python3 -c "from database import init_db; init_db()"

# Start application
echo ""
echo "🚀 Starting application..."
echo "   Access at: http://localhost:8000"
echo "   API Docs: http://localhost:8000/docs"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

python3 main.py
