import os
import sys
import webbrowser
from threading import Timer
import uvicorn

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi_app import app

def open_browser():
    webbrowser.open_new("http://127.0.0.1:5000")

def start_server():
    Timer(1.5, open_browser).start()
    uvicorn.run(app, host="127.0.0.1", port=5000, log_level="info")

if __name__ == "__main__":
    start_server()
