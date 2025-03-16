from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
import hashlib
import json
import time
import os
import uuid
import secrets
import random

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Generate a random secret key

# Files for storing blockchain, ledger, wallets, and users
BLOCKCHAIN_FILE = "data/blockchain.json"
LEDGER_FILE = "data/ledger.json"
WALLETS_FILE = "data/wallets.json"
USERS_FILE = "data/users.json"
TRANSACTIONS_FILE = "data/transactions.json"  # New file for transaction history

# Blockchain data
blockchain = []
ledger = {}  # Stores wallet balances
wallets = {}  # Stores wallet information
users = {}  # Stores user information
transactions = []  # Stores transaction history
reward_per_block = 0.001  # Reward per mined block
difficulty_bits = 25  # Increased difficulty
target = 2**(256 - difficulty_bits)

def load_data():
    """Load blockchain, ledger, wallets, users, and transactions from files."""
    global blockchain, ledger, wallets, users, transactions
    if os.path.exists(BLOCKCHAIN_FILE):
        with open(BLOCKCHAIN_FILE, "r") as f:
            blockchain = json.load(f)
    else:
        blockchain.append(create_genesis_block())
        save_data()

    if os.path.exists(LEDGER_FILE):
        with open(LEDGER_FILE, "r") as f:
            ledger = json.load(f)
    
    if os.path.exists(WALLETS_FILE):
        with open(WALLETS_FILE, "r") as f:
            wallets = json.load(f)
    
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r") as f:
            users = json.load(f)
            
    if os.path.exists(TRANSACTIONS_FILE):
        with open(TRANSACTIONS_FILE, "r") as f:
            transactions = json.load(f)

def save_data():
    """Save blockchain, ledger, wallets, users, and transactions to files."""
    with open(BLOCKCHAIN_FILE, "w") as f:
        json.dump(blockchain, f, indent=4)

    with open(LEDGER_FILE, "w") as f:
        json.dump(ledger, f, indent=4)
        
    with open(WALLETS_FILE, "w") as f:
        json.dump(wallets, f, indent=4)
    
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)
        
    with open(TRANSACTIONS_FILE, "w") as f:
        json.dump(transactions, f, indent=4)

def create_genesis_block():
    """Create the Genesis Block."""
    return {
        "index": 0,
        "timestamp": time.time(),
        "previous_hash": "0" * 64,
        "nonce": 0,
        "hash": hashlib.sha256("genesis".encode()).hexdigest(),
        "miner": "system"
    }

def hash_password(password):
    """Hash a password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

def create_wallet(username):
    """Create a new wallet with a unique address for a user."""
    wallet_id = str(uuid.uuid4()).replace('-', '')
    wallet_address = f"{wallet_id[:16]}"
    wallets[wallet_address] = {"created_at": time.time(), "owner": username}
    
    # Assign the wallet to the user
    users[username]["wallet"] = wallet_address
    
    # Initialize wallet balance
    ledger[wallet_address] = 0
    
    save_data()
    return wallet_address

def validate_block(block, previous_block):
    """Validates a mined block."""
    expected_hash = hashlib.sha256(
        f"{block['index']}{block['timestamp']}{block['previous_hash']}{block['nonce']}".encode()
    ).hexdigest()
    
    return (block['previous_hash'] == previous_block['hash'] and
            int(expected_hash, 16) < target and
            block['hash'] == expected_hash)

def create_transaction(sender, receiver, amount, description=""):
    """Create a new transaction between wallets."""
    # Check if sender has enough funds
    sender_balance = ledger.get(sender, 0)
    if sender_balance < amount:
        return False, "Insufficient funds"
    
    # Check if receiver wallet exists
    if receiver not in wallets:
        return False, "Receiver wallet not found"
    
    # Update ledger
    ledger[sender] = sender_balance - amount
    ledger[receiver] = ledger.get(receiver, 0) + amount
    
    # Record transaction
    transaction = {
        "id": str(uuid.uuid4()),
        "timestamp": time.time(),
        "sender": sender,
        "receiver": receiver,
        "amount": amount,
        "description": description,
        "sender_username": wallets[sender]["owner"],
        "receiver_username": wallets[receiver]["owner"]
    }
    
    transactions.append(transaction)
    save_data()
    
    return True, transaction

# Authentication routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username in users and users[username]["password"] == hash_password(password):
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handle user registration."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if username in users:
            flash('Username already exists')
        elif password != confirm_password:
            flash('Passwords do not match')
        else:
            users[username] = {
                "password": hash_password(password),
                "created_at": time.time(),
                "wallet": None  # User starts with no wallet
            }
            save_data()
            session['username'] = username
            return redirect(url_for('dashboard'))
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    """Handle user logout."""
    session.pop('username', None)
    return redirect(url_for('login'))

# Web interface routes
@app.route('/')
def index():
    """Redirect to login page."""
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    """User dashboard."""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    wallet_address = users[username].get("wallet")
    
    # Get wallet details
    wallet_details = None
    if wallet_address:
        wallet_details = {
            "address": wallet_address,
            "balance": ledger.get(wallet_address, 0)
        }
    
    # Get user's transactions
    user_transactions = []
    if wallet_address:
        user_transactions = [tx for tx in transactions 
                           if tx["sender"] == wallet_address or tx["receiver"] == wallet_address]
        user_transactions.sort(key=lambda x: x["timestamp"], reverse=True)
    
    return render_template('dashboard.html', 
                           username=username,
                           wallet=wallet_details,
                           blockchain=blockchain,
                           transactions=user_transactions,
                           reward=reward_per_block,
                           difficulty=difficulty_bits)

@app.route('/create_wallet', methods=['POST'])
def handle_create_wallet():
    """Create a new wallet for the logged-in user."""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    
    # Check if user already has a wallet
    if users[username].get("wallet"):
        flash('You already have a wallet. Only one wallet per account is allowed.')
        return redirect(url_for('dashboard'))
    
    wallet_address = create_wallet(username)
    flash(f'Your wallet has been created: {wallet_address}')
    return redirect(url_for('dashboard'))

@app.route('/send', methods=['GET', 'POST'])
def send_funds():
    """Handle sending funds between wallets."""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    wallet_address = users[username].get("wallet")
    
    # Check if user has a wallet
    if not wallet_address:
        flash('You need to create a wallet first.')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        receiver = request.form.get('receiver')
        amount = float(request.form.get('amount'))
        description = request.form.get('description', '')
        
        if amount <= 0:
            flash('Amount must be greater than zero.')
            return redirect(url_for('send'))
        
        success, result = create_transaction(wallet_address, receiver, amount, description)
        
        if success:
            flash('Transaction completed successfully!')
            return redirect(url_for('dashboard'))
        else:
            flash(f'Transaction failed: {result}')
            return redirect(url_for('send'))
    
    # GET request - display the send form
    wallet_balance = ledger.get(wallet_address, 0)
    
    # Get list of all other users with wallets for the dropdown
    other_users = []
    for user, data in users.items():
        if user != username and data.get("wallet"):
            other_users.append({
                "username": user,
                "wallet": data["wallet"]
            })
    
    return render_template('send.html', 
                           wallet_address=wallet_address,
                           balance=wallet_balance,
                           other_users=other_users)

@app.route('/transactions')
def view_transactions():
    """View all transactions."""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Sort transactions by timestamp (newest first)
    sorted_transactions = sorted(transactions, key=lambda x: x["timestamp"], reverse=True)
    
    return render_template('transactions.html', transactions=sorted_transactions)

# Original API routes
@app.route('/get_block', methods=['GET'])
def get_last_block():
    """Returns the last block in the blockchain."""
    return jsonify(blockchain[-1])

@app.route('/submit_block', methods=['POST'])
def submit_block():
    """Receives a mined block and validates it."""
    block = request.json
    miner_wallet = block.get("miner")

    if not miner_wallet or not validate_block(block, blockchain[-1]):
        return jsonify({"status": "Invalid block"}), 400

    # Verify wallet exists
    if miner_wallet not in wallets:
        return jsonify({"status": "Unknown wallet"}), 400

    # Append the block to the blockchain
    blockchain.append(block)

    # Reward the miner
    reward = (1+((random.randint(1, 50)/100)))*reward_per_block
    ledger[miner_wallet] = ledger.get(miner_wallet, 0) + reward
    
    # Record mining reward as a transaction
    mining_transaction = {
        "id": str(uuid.uuid4()),
        "timestamp": time.time(),
        "sender": "MINING_REWARD",
        "receiver": miner_wallet,
        "amount": reward,
        "description": f"Mining reward for block #{block['index']}",
        "sender_username": "System",
        "receiver_username": wallets[miner_wallet]["owner"]
    }
    transactions.append(mining_transaction)

    # Save updated blockchain and ledger
    save_data()

    return jsonify({"status": "Block accepted", "index": block['index'], "reward": reward}), 200

@app.route('/chain', methods=['GET'])
def get_chain():
    """Returns the entire blockchain."""
    return jsonify(blockchain)

@app.route('/wallet/<wallet_address>', methods=['GET'])
def get_wallet_balance(wallet_address):
    """Returns the balance of a given wallet."""
    balance = ledger.get(wallet_address, 0)
    return jsonify({"wallet": wallet_address, "balance": balance})

@app.route('/api/verify_wallet', methods=['POST'])
def verify_wallet():
    """Verify if a wallet belongs to a user (for mining software)."""
    data = request.json
    wallet_address = data.get('wallet_address')
    username = data.get('username')
    password = data.get('password')
    
    if (username in users and 
        users[username]["password"] == hash_password(password) and 
        users[username].get("wallet") == wallet_address):
        return jsonify({"status": "valid", "wallet": wallet_address}), 200
    else:
        return jsonify({"status": "invalid"}), 401

@app.route('/api/transactions', methods=['GET'])
def get_transactions():
    """Returns all transactions."""
    return jsonify(transactions)

@app.route('/api/send', methods=['POST'])
def api_send_funds():
    """API endpoint for sending funds between wallets."""
    data = request.json
    sender = data.get('sender')
    receiver = data.get('receiver')
    amount = data.get('amount')
    description = data.get('description', '')
    username = data.get('username')
    password = data.get('password')
    
    # Verify user credentials and wallet ownership
    if not (username in users and 
            users[username]["password"] == hash_password(password) and 
            users[username].get("wallet") == sender):
        return jsonify({"status": "Authentication failed"}), 401
    
    if not isinstance(amount, (int, float)) or amount <= 0:
        return jsonify({"status": "Invalid amount"}), 400
    
    success, result = create_transaction(sender, receiver, amount, description)
    
    if success:
        return jsonify({"status": "success", "transaction": result}), 200
    else:
        return jsonify({"status": "failed", "message": result}), 400

if __name__ == '__main__':
    load_data()  # Load blockchain and ledger on startup
    app.run(host='0.0.0.0', port=5000, debug=True)