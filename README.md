# PythonCoin (PyC) Mining System

## Overview
PythonCoin (PyC) is a blockchain-based mining system where users can mine coins by solving mathematical equations. The system features a REST API for communication and uses an SQLite ledger to track transactions.

## Features
- Centralized server that distributes mining equations
- Reward system based on solution accuracy
- Secure user authentication
- SQLite-based ledger for transaction tracking
- REST API for client-server communication

## Installation
1. Clone the repository:
   ```sh
   git clone https://github.com/anhpham-dev/pycoin
   ```
2. Navigate to the project directory:
   ```sh
   cd pythoncoin
   ```
3. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```

## Running the Server
To start the server, run:
```sh
python server.py
```
The server will start on `http://0.0.0.0:5000/` by default.

## API Endpoints
- `/register`: Register a new user
- `/login`: Authenticate a user
- `/get_block`: Get the latest blockchain block
- `/submit_block`: Submit a mined block
- `/wallet/<wallet_address>`: Get wallet balance
- `/api/transactions`: Retrieve transaction history
- `/api/send`: Transfer funds between wallets

# How to Use the Miners

## Setting Up the Miner
1. Ensure you have Python installed on your machine.
2. Download the mining client from the repository.
3. Open a terminal or command prompt and navigate to the mining client directory.
4. Run the mining client with:
   ```sh
   python miner.py --address <your-wallet> --worker <your-worker-name> --serverurl https://62d1-27-64-57-130.ngrok-free.app
   ```

## Hashrate Measurement
The miner's hashrate is displayed in H/s (hashes per second). If the hashrate exceeds 1,000 H/s, it is converted automatically:
- 1,000 H/s = 1 KH/s (Kilohash per second)
- 1,000,000 H/s = 1 MH/s (Megahash per second)

