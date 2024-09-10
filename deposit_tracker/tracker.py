# tracker.py
from web3 import Web3
from dotenv import load_dotenv
import os
import logging
from eth_abi.abi import decode
from database import Deposit, save_deposit
from telegram_alerts.alert import telegram_alert

# Beacon Deposit Contract address
DEPOSIT_CONTRACT_ADDRESS = '0x00000000219ab540356cBB839Cbe05303d7705Fa'

# Load the .env file from the main directory
dotenv_path = os.path.join(os.path.dirname(__file__), '..', '.env')
load_dotenv(dotenv_path)

logging.basicConfig(filename='logs/eth_deposit_tracker.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_w3():
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
    
    return w3

def process_deposit_event(w3, event, db):
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
        telegram_alert()
        logging.info(result)
        
        print("New Deposit {")
        print(f"    blockNumber: {deposit.blockNumber};")
        print(f"    blockTimestamp: {deposit.blockTimestamp};")
        print(f"    fee: {deposit.fee} ETH;")
        print(f"    hash: {deposit.hash};")
        print(f"    pubkey: {deposit.pubkey};")
        print("}")
        print()
    
    except Exception as e:
        logging.error(f"Error processing deposit event: {e}")

def check_new_deposits(w3, db, last_processed_block):
    latest_block = w3.eth.get_block('latest')['number']
    
    if latest_block <= last_processed_block:
        return last_processed_block

    deposit_event_signature = w3.keccak(text="DepositEvent(bytes,bytes,bytes,bytes,bytes)").hex()
    
    for block_number in range(last_processed_block + 1, latest_block + 1):
        block = w3.eth.get_block(block_number, full_transactions=True)
        
        for tx in block['transactions']:
            if tx['to'] and tx['to'].lower() == DEPOSIT_CONTRACT_ADDRESS.lower():
                receipt = w3.eth.get_transaction_receipt(tx['hash'])
                for log in receipt['logs']:
                    if log['topics'][0].hex() == deposit_event_signature:
                        process_deposit_event(w3, log, db)
    
    return latest_block