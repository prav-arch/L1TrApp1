#!/usr/bin/env python3
"""
Setup script for Mistral AI model integration
"""

import os
import sys
import subprocess
import shutil

def check_python_packages():
    """Check and install required Python packages"""
    packages = ['llama-cpp-python']
    
    for package in packages:
        try:
            __import__(package.replace('-', '_'))
            print(f"✓ {package} is already installed")
        except ImportError:
            print(f"Installing {package}...")
            try:
                subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
                print(f"✓ {package} installed successfully")
            except subprocess.CalledProcessError:
                print(f"✗ Failed to install {package}")
                return False
    return True

def setup_model_directory():
    """Create and setup model directory"""
    model_dir = "/tmp/llm_models"
    model_file = "mistral-7b-instruct-v0.2.Q4_K_M.gguf"
    
    # Create directory if it doesn't exist
    os.makedirs(model_dir, exist_ok=True)
    print(f"✓ Model directory created: {model_dir}")
    
    model_path = os.path.join(model_dir, model_file)
    
    if os.path.exists(model_path):
        print(f"✓ Model file already exists: {model_path}")
        return True
    else:
        print(f"✗ Model file not found: {model_path}")
        print("\nTo complete setup:")
        print("1. Download or copy mistral-7b-instruct-v0.2.Q4_K_M.gguf from your local server")
        print(f"2. Place it in: {model_dir}/")
        print("3. Run this script again to verify")
        return False

def test_model_loading():
    """Test if the model can be loaded"""
    model_path = "/tmp/llm_models/mistral-7b-instruct-v0.2.Q4_K_M.gguf"
    
    if not os.path.exists(model_path):
        print("✗ Model file not found, skipping load test")
        return False
        
    try:
        import llama_cpp
        print("Testing model loading...")
        
        # Try to load the model with minimal settings
        llm = llama_cpp.Llama(
            model_path=model_path,
            n_ctx=512,
            verbose=False
        )
        
        # Simple test prompt
        response = llm("Hello, this is a test.", max_tokens=10, echo=False)
        print("✓ Model loaded and responded successfully")
        print(f"Test response: {response['choices'][0]['text'].strip()}")
        return True
        
    except Exception as e:
        print(f"✗ Model loading failed: {str(e)}")
        return False

def main():
    print("🔧 Setting up Mistral AI for L1 Troubleshooting System")
    print("=" * 60)
    
    # Step 1: Check Python packages
    print("\n1. Checking Python packages...")
    if not check_python_packages():
        print("Failed to install required packages. Please install manually:")
        print("pip install llama-cpp-python")
        return
    
    # Step 2: Setup directories
    print("\n2. Setting up model directory...")
    model_available = setup_model_directory()
    
    # Step 3: Test model if available
    if model_available:
        print("\n3. Testing model loading...")
        if test_model_loading():
            print("\n🎉 Setup complete! The Mistral AI integration is ready to use.")
        else:
            print("\n⚠️ Model file exists but cannot be loaded. Check the file integrity.")
    else:
        print("\n⚠️ Setup incomplete. Please copy the model file as instructed above.")
    
    print(f"\nModel location: /tmp/llm_models/mistral-7b-instruct-v0.2.Q4_K_M.gguf")
    print("Run the web application and click 'Get Recommendations' to test the integration.")

if __name__ == "__main__":
    main()