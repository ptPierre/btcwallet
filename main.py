import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTextEdit, QLabel, QLineEdit, QMessageBox
)
from key_generation import (
    generate_random_entropy,
    entropy_with_checksum,
    split_into_parts,
    convert_parts_to_words,
    mnemonic_to_seed,
    derive_master_key_and_chain_code,
    derive_master_public_key,
    derive_child_key,
    derive_child_key_at_index,
    private_key_to_testnet_address,
    send_testnet_transaction,
    get_testnet_balance
)


class BitcoinKeyGenerator(QWidget):
    def __init__(self):
        super().__init__()
        self.master_private_key = None
        self.master_chain_code = None
        self.mnemonic_phrase = None
        self.master_public_key = None
        self.child_keys = []
        self.initUI()


    def initUI(self):
        self.setWindowTitle('Bitcoin Testnet Wallet')
        self.setGeometry(100, 100, 800, 600)

        layout = QVBoxLayout()

        # Generate Wallet Button
        self.generate_button = QPushButton('Generate Wallet', self)
        self.generate_button.clicked.connect(self.generate_wallet)

        # Address Display
        self.address_label = QLabel('Your Testnet Address:', self)
        self.address_text = QLineEdit(self)
        self.address_text.setReadOnly(True)

        # Balance Display
        self.balance_label = QLabel('Balance: 0 BTC', self)

        # Refresh Balance Button
        self.refresh_balance_button = QPushButton('Refresh Balance', self)
        self.refresh_balance_button.clicked.connect(self.refresh_balance)

        # Send Funds Section
        send_layout = QHBoxLayout()
        self.to_address_input = QLineEdit(self)
        self.to_address_input.setPlaceholderText('Recipient Address')
        self.amount_input = QLineEdit(self)
        self.amount_input.setPlaceholderText('Amount (in BTC)')

        self.send_button = QPushButton('Send Funds', self)
        self.send_button.clicked.connect(self.send_funds)

        send_layout.addWidget(self.to_address_input)
        send_layout.addWidget(self.amount_input)
        send_layout.addWidget(self.send_button)

        # View Keys Button
        self.view_keys_button = QPushButton('View All Keys', self)
        self.view_keys_button.clicked.connect(self.view_keys)

        # Output Text Area
        self.output_label = QLabel('Output:', self)
        self.output_text = QTextEdit(self)
        self.output_text.setReadOnly(True)

        # Add widgets to layout
        layout.addWidget(self.generate_button)
        layout.addWidget(self.address_label)
        layout.addWidget(self.address_text)
        layout.addWidget(self.balance_label)
        layout.addWidget(self.refresh_balance_button)
        layout.addLayout(send_layout)
        layout.addWidget(self.view_keys_button)
        layout.addWidget(self.output_label)
        layout.addWidget(self.output_text)

        self.setLayout(layout)


    def generate_wallet(self):
        # Step 1: Generate random 128-bit entropy
        entropy = generate_random_entropy()

        # Step 2: Append checksum to the entropy
        entropy_bits_with_checksum = entropy_with_checksum(entropy)

        # Step 3: Split the entropy + checksum into 11-bit parts
        parts = split_into_parts(entropy_bits_with_checksum)

        # Step 4: Convert parts to mnemonic words
        mnemonic_words = convert_parts_to_words(parts)

        # Step 5: Join words to form the mnemonic phrase
        self.mnemonic_phrase = ' '.join(mnemonic_words)

        # Step 6: Derive the seed from the mnemonic phrase
        passphrase = ""  # Optional passphrase
        original_seed = mnemonic_to_seed(self.mnemonic_phrase, passphrase)

        # Step 7: Derive the master private key and chain code from the seed
        self.master_private_key, self.master_chain_code = derive_master_key_and_chain_code(original_seed)

        # Step 8: Derive the master public key from the master private key
        self.master_public_key = derive_master_public_key(self.master_private_key)

        # Derive a child key (e.g., index 0)
        child_private_key, child_chain_code = derive_child_key(
            self.master_private_key, self.master_chain_code, index=0, hardened=False
        )

        self.child_keys = [{
            'index': 0,
            'private_key': child_private_key,
            'chain_code': child_chain_code
        }]

        # Get the testnet address from the child private key
        address = private_key_to_testnet_address(child_private_key)
        self.address_text.setText(address)

        # Update balance
        balance = get_testnet_balance(child_private_key)
        self.balance_label.setText(f'Balance: {balance} BTC')

        QMessageBox.information(self, 'Wallet Generated', f'New wallet generated with address:\n{address}')


    def refresh_balance(self):
        if not self.child_keys:
            QMessageBox.warning(self, 'Error', 'Please generate a wallet first.')
            return

        child_private_key = self.child_keys[0]['private_key']
        balance = get_testnet_balance(child_private_key)
        self.balance_label.setText(f'Balance: {balance} BTC')
        QMessageBox.information(self, 'Balance Updated', f'Balance: {balance} BTC')


    def send_funds(self):
        if not self.child_keys:
            QMessageBox.warning(self, 'Error', 'Please generate a wallet first.')
            return

        to_address = self.to_address_input.text()
        amount_text = self.amount_input.text()

        try:
            amount = float(amount_text)
        except ValueError:
            QMessageBox.warning(self, 'Error', 'Please enter a valid amount.')
            return

        # Use the first child private key for sending funds
        child_private_key = self.child_keys[0]['private_key']

        try:
            tx_hash = send_testnet_transaction(child_private_key, to_address, amount)
            balance = get_testnet_balance(child_private_key)
            self.balance_label.setText(f'Balance: {balance} BTC')
            QMessageBox.information(self, 'Transaction Sent', f'Transaction sent with tx hash:\n{tx_hash}')
        except Exception as e:
            QMessageBox.warning(self, 'Error', f'Failed to send transaction:\n{e}')


    def view_keys(self):
        if not self.master_private_key:
            QMessageBox.warning(self, 'Error', 'Please generate a wallet first.')
            return

        output = f"Mnemonic Phrase:\n{self.mnemonic_phrase}\n\n"
        output += f"Master Private Key:\n{self.master_private_key}\n\n"
        output += f"Master Public Key:\n{self.master_public_key}\n\n"

        for idx, key_info in enumerate(self.child_keys):
            output += f"Child Key {idx} (Index {key_info['index']}):\n"
            output += f"Private Key: {key_info['private_key']}\n"
            output += f"Chain Code: {key_info['chain_code']}\n"

            # Get the address
            address = private_key_to_testnet_address(key_info['private_key'])
            output += f"Testnet Address: {address}\n\n"

        self.output_text.setPlainText(output)



if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = BitcoinKeyGenerator()
    window.show()
    sys.exit(app.exec_())
