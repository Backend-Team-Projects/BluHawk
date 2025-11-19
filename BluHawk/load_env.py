import os
from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv()

EMAIL_HOST_USER = os.getenv('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = os.getenv('EMAIL_HOST_PASSWORD')
ADMIN_EMAIL = os.getenv('ADMIN_EMAIL')
SECRET_KEY = os.getenv('SECRET_KEY')
VIRUS_TOTAL = os.getenv("VIRUS_TOTAL")
POSTGRESQL_PASSWORD = os.getenv("POSTGRESQL_PASSWORD")
SUPERUSER_PASSWORD = os.getenv("SUPERUSER_PASSWORD")
SHODAN_API_KEY = os.getenv('SHODAN_API_KEY')   
AlienVault_API = os.getenv('AlienVault_API')
EXA_API = os.getenv('EXA_API')

# site_domain = "https://bluhawkscan.com/"
site_domain = "http://localhost:3001/"
TIRRENO_URL = "https://admin.bluhawkscan.com/"
TIRRENO_API = os.getenv('TIRRENO_API')
MORALIS = os.getenv('MORALIS')
DB_PORT = os.getenv("DB_PORT", '5432')

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

PGPASSWORD = os.getenv("POSTGRESQL_PASSWORD")