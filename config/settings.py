import os
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))

BASE_DIR     = os.path.dirname(os.path.dirname(__file__))
DATA_DIR     = os.path.join(BASE_DIR, 'data')
REPORTS_DIR  = os.path.join(DATA_DIR, 'reports')
SESSIONS_DIR = os.path.join(DATA_DIR, 'sessions')
LOGS_DIR     = os.path.join(DATA_DIR, 'logs')
DB_PATH      = os.path.join(DATA_DIR, 'logs', 'netstrike.db')

FLASK_HOST   = '0.0.0.0'
FLASK_PORT   = 5000
SECRET_KEY   = os.getenv('SECRET_KEY', 'netstrike')

OPENAI_KEY   = os.getenv('OPENAI_API_KEY')
OPENAI_MODEL = os.getenv('OPENAI_MODEL', 'gpt-4o')

MSF_HOST     = os.getenv('MSF_HOST', '127.0.0.1')
MSF_PORT     = int(os.getenv('MSF_PORT', 55553))
MSF_USER     = os.getenv('MSF_USER', 'msf')
MSF_PASS     = os.getenv('MSF_PASS', 'msfpass')
