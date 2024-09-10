import telebot
import os
import sys
from dotenv import load_dotenv

# Add the main folder to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Load the .env file from the main directory
dotenv_path = os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')), '.env')
load_dotenv(dotenv_path)

# Create a Telegram bot instance
bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
bot = telebot.TeleBot(bot_token)

# Get the list of recipients from the .env file
recipients_str = os.getenv('TELEGRAM_RECIPIENT_IDS')
if recipients_str:
    recipients = [int(recipient_id) for recipient_id in recipients_str.split(',')]
else:
    recipients = []

def send_message_to_user(chat_id, message):
    try:
        bot.send_message(chat_id=chat_id, text=message)
        print(f"Message sent to {chat_id}")
    except Exception as e:
        print(f"Error sending message to {chat_id}: {e}")

def telegram_alert():
    message = "New deposits have been made."
    for recipient_id in recipients:
        send_message_to_user(recipient_id, message)
