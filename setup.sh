#!/bin/bash
# ESP32 FirmGuard - Quick Setup Script

echo "🚀 ESP32 FirmGuard Setup"
echo "========================"
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 not found. Please install Python 3.8+"
    exit 1
fi

echo "✓ Python3 found: $(python3 --version)"
echo ""

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
    echo "✓ Virtual environment created"
else
    echo "✓ Virtual environment already exists"
fi

echo ""
echo "📥 Installing dependencies..."
source venv/bin/activate

# Install core dependencies
pip install --upgrade pip
pip install numpy pandas scikit-learn pyyaml requests

echo ""
echo "✅ Core dependencies installed!"
echo ""
echo "📋 Optional dependencies:"
echo "  - XGBoost (for better ML): pip install xgboost"
echo "  - Ollama support: Already configured (just run 'ollama serve')"
echo ""
echo "🧪 To test:"
echo "  1. Activate venv: source venv/bin/activate"
echo "  2. Run test: python scripts/run_test_example.py"
echo ""
echo "✨ Setup complete!"


