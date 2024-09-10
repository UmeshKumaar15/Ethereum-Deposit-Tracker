# tracker.py

from web3 import Web3
from dotenv import load_dotenv
import os
import logging
import time
from eth_abi.abi import decode
from datetime import datetime, timedelta
from database import Deposit, get_db, save_deposit

# Load environment variables and set up logging
load_dotenv()
logging.basicConfig(filename='logs/eth_deposit_tracker.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Set up Alchemy connection
alchemy_api_key = os.getenv("ALCHEMY_API_KEY")
if not alchemy_api_key:
    raise ValueError("API key not found in environment variables.")

alchemy_url = f"https://eth-mainnet.alchemyapi.io/v2/{alchemy_api_key}"
w3 = Web3(Web3.HTTPProvider(alchemy_url))

if w3.is_connected():
    print("Successfully connected to Ethereum!")
    logging.info("Successfully connected to Ethereum!")
else:
    print("Connection failed.")
    logging.error("Connection failed. URL: %s", alchemy_url)

# Beacon Deposit Contract address
DEPOSIT_CONTRACT_ADDRESS = '0x00000000219ab540356cBB839Cbe05303d7705Fa'

def get_block_number_from_hours_ago(hours):
    latest_block = w3.eth.get_block('latest')
    current_timestamp = latest_block['timestamp']
    target_timestamp = current_timestamp - hours * 3600  # Convert hours to seconds

    left, right = 1, latest_block['number']
    while left <= right:
        mid = (left + right) // 2
        block = w3.eth.get_block(mid)
        if block['timestamp'] < target_timestamp:
            left = mid + 1
        elif block['timestamp'] > target_timestamp:
            right = mid - 1
        else:
            return mid
    return right

def process_deposit_event(event, db):
    try:
        transaction_hash = event['transactionHash'].hex()
        
        # Fetch transaction and block data
        tx = w3.eth.get_transaction(transaction_hash)
        block = w3.eth.get_block(tx['blockNumber'])
        
        pubkey, _, amount, _, _ = decode(
            ['bytes', 'bytes', 'bytes', 'bytes', 'bytes'],
            event['data']
        )
        
        # Calculate fee (gas used * gas price)
        tx_receipt = w3.eth.get_transaction_receipt(transaction_hash)
        fee = w3.from_wei(tx_receipt['gasUsed'] * tx['gasPrice'], 'ether')
        
        deposit = Deposit(
            blockNumber=tx['blockNumber'],
            blockTimestamp=block['timestamp'],
            fee=fee,
            hash=transaction_hash,
            pubkey='0x' + pubkey.hex(),
        )
        
        result = save_deposit(db, deposit)
        logging.info(result)
        
        print("Deposit {")
        print(f"    blockNumber: {deposit.blockNumber};")
        print(f"    blockTimestamp: {deposit.blockTimestamp};")
        print(f"    fee: {deposit.fee} ETH;")
        print(f"    hash: {deposit.hash};")
        print(f"    pubkey: {deposit.pubkey};")
        print("}")
        print()
    
    except Exception as e:
        logging.error(f"Error processing deposit event: {e}")

def fetch_deposits_last_4_hours(db):
    start_block = get_block_number_from_hours_ago(4)
    end_block = w3.eth.get_block('latest')['number']

    deposit_event_signature = w3.keccak(text="DepositEvent(bytes,bytes,bytes,bytes,bytes)").hex()
    
    print(f"Fetching deposits from block {start_block} to {end_block}...")
    
    for block_number in range(start_block, end_block + 1):
        block = w3.eth.get_block(block_number, full_transactions=True)
        
        for tx in block['transactions']:
            if tx['to'] and tx['to'].lower() == DEPOSIT_CONTRACT_ADDRESS.lower():
                receipt = w3.eth.get_transaction_receipt(tx['hash'])
                for log in receipt['logs']:
                    if log['topics'][0].hex() == deposit_event_signature:
                        process_deposit_event(log, db)

def main():
    db = next(get_db())
    
    while True:
        try:
            fetch_deposits_last_4_hours(db)
            print("Finished processing deposits from the last 4 hours. Waiting for 10 minutes before next check...")
            time.sleep(600)  # Wait for 10 minutes before checking again
        except Exception as e:
            logging.error(f"Error in main loop: {e}")
            time.sleep(60)  # Wait for 1 minute before retrying if there's an error

if __name__ == "__main__":
    main()