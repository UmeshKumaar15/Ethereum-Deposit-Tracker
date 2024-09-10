from sqlalchemy import create_engine, Column, Integer, String, Float, BigInteger
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os
import sys
from dotenv import load_dotenv

# Add the main folder to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Load the .env file from the main directory
dotenv_path = os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')), '.env')
load_dotenv(dotenv_path)

# Set up PostgreSQL connection
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("Database URL not found in environment variables.")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Define Deposit model
class Deposit(Base):
    __tablename__ = "deposits"

    id = Column(Integer, primary_key=True, index=True)
    blockNumber = Column(BigInteger)
    blockTimestamp = Column(BigInteger)
    fee = Column(Float)
    hash = Column(String, unique=True, index=True)
    pubkey = Column(String)

# Create tables
Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def save_deposit(db, deposit):
    try:
        existing_deposit = db.query(Deposit).filter_by(hash=deposit.hash).first()
        if not existing_deposit:
            db.add(deposit)
            db.commit()
            return f"New deposit saved: {deposit.hash}"
        else:
            return f"Deposit already exists in database: {deposit.hash}"
    except Exception as e:
        db.rollback()
        raise e