# main.py
import time
import logging
from tracker import get_w3, check_new_deposits
from database import get_db

def main():
    db = next(get_db())
    w3 = get_w3()  # Get the Web3 instance
    last_processed_block = w3.eth.get_block('latest')['number']
    
    while True:
        try:
            last_processed_block = check_new_deposits(w3, db, last_processed_block)
            print(f"Processed blocks up to {last_processed_block}. Waiting for 60 seconds before next check...")
            time.sleep(60)  # Wait for 60 seconds before checking again
        except Exception as e:
            logging.error(f"Error in main loop: {e}")
            time.sleep(60) # Wait for 60 seconds before retrying if there's an error

if __name__ == "__main__":
    main()
