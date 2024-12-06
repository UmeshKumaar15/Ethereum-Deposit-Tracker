# Ethereum Deposit Tracker

## Project Overview

The Ethereum Deposit Tracker monitors and records Ethereum deposits on the Beacon Deposit Contract. It tracks deposits, stores data in a PostgreSQL database, sends alerts via Telegram, and configures Grafana dashboards for visualizing the data.

## Dashboard

<img src="readme_images/dashboard.png" alt="Dashboard" width="800"/>


## Features

- Tracks Ethereum deposits on the Beacon Deposit Contract.
- Stores deposit data in a PostgreSQL database.
- Uses proper logging of the API status and write operations in the database.
- Sends Telegram alerts about new deposits.
- Configures a Grafana dashboard to display deposit volume graphs, fee statistics, and latest deposit data.
  

## File Structure
```bash
ethereum-deposit-tracker
|
|-- deposit_tracker
|   |-- main.py
|   |-- database.py
|   |-- tracker.py
|   |-- view_data.pgsql
|   |-- logs
|       |--eth_deposit_tracker.log
|
|-- grafana
|   |-- dashboard_config.json
|
|-- telegram_alerts
|   |-- alert.py
|
|-- requirements.txt
```


## Installation and Setup

### Prerequisites

- Python 3.x
- PostgreSQL
- Telegram Bot API Token
- Grafana

### 1. Clone the Repository

```bash
git clone <repository-url>
cd ethereum-deposit-tracker
```

### 2. Set Up a Virtual Environment

```bash
python -m venv venv
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables

Create a .env file in the root directory with the following variables:

```env
ALCHEMY_API_KEY=your_alchemy_api_key
DATABASE_URL=your_postgresql_database_url
TELEGRAM_BOT_TOKEN=your_telegram_bot_token
TELEGRAM_RECIPIENT_IDS=comma_separated_recipient_ids
```

- ALCHEMY_API_KEY: Get your Alchemy API key for Ethereum here https://dashboard.alchemy.com
- DATABASE_URL: PostgreSQL connection URL is ostgresql+psycopg2://postgres:<your_user_name>@localhost/deposits" (After downloading PostgreSQL Refer step 5)
- TELEGRAM_BOT_TOKEN: Refer BotFather to create a bot and get the Bot token - https://telegram.me/BotFather
- TELEGRAM_RECIPIENT_IDS: Comma-separated list of Telegram user IDs to receive alerts. (Use userinfobot in telegram to get userids)
  

### 5. Set Up PostgreSQL Database

- Download PostgreSQL from https://www.postgresql.org/download/
- Database will be created by running main.py (later in step 7).

### 6. Configure Grafana

- Download Grafana
- Use http://localhost:3000 the port of localhost grafana to visualize your database
- Place your Grafana configuration json from grafana/dashboard_config.json in your grafana's configuration settings

### 7. Run the Application

```
python deposit_tracker/main.py
```
## Telegram Alert Image
<img src="readme_images/telegram_bot_image.jpg" alt="Telegram" width="200"/>


This script will start tracking Ethereum deposits and processing them as described in the main.py file.
We can also see the added deposit information by running a query view_data.pgsql and also transcript messages will be printed and we can also access the details in grafana dashboard
Every data entry/error/change is logged.

