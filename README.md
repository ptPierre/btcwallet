# Bitcoin Testnet Wallet Generator

This project contains Python code to generate Bitcoin testnet wallets, including both private/public keys and addresses, utilizing hierarchical deterministic (HD) key derivation techniques. The project features a PyQt5-based graphical user interface that allows users to generate wallets, view their private/public keys, check testnet balances, and send Bitcoin testnet transactions.

The solution consists of two main components:

- **key_generation.py**: Implements the core cryptographic operations needed for wallet generation and key derivation.
- **main.py**: Provides the GUI for user interaction, allowing wallet generation, viewing keys, checking balance, and sending transactions on the Bitcoin testnet.

The audience for this README is experienced developers who are familiar with cryptographic concepts and hierarchical key derivation (such as BIP-32, BIP-39). The code relies on Python's cryptographic libraries and `bit` for key and address management on the Bitcoin testnet.

## Key Features

- **Mnemonic Phrase Generation**: The code uses BIP-39-like word lists to convert entropy into a human-readable mnemonic phrase.
- **Master and Child Key Derivation**: Utilizes HMAC-SHA512 to derive a master key and chain code, enabling hierarchical deterministic key generation.
- **Bitcoin Testnet Address Management**: Integration with the `bit` library allows generation of testnet addresses, querying balance, and sending transactions.
- **Graphical User Interface**: A PyQt5-based application to generate and manage wallets easily.

## Code Walkthrough

### key_generation.py

This module is responsible for the cryptographic backend for the wallet generator, which includes entropy generation, checksum calculation, and key derivation.

#### Steps of Wallet Generation

1. **Generate Entropy**:
   - `generate_random_entropy()` generates 128 bits of entropy (`os.urandom(16)`).

2. **Calculate Checksum**:
   - The function `get_checksum()` calculates a 4-bit checksum from the SHA-256 hash of the entropy.

3. **Append Checksum to Entropy**:
   - The function `entropy_with_checksum()` appends the checksum to the binary form of the entropy, resulting in 132 bits.

4. **Split Binary Data into 11-bit Parts**:
   - `split_into_parts()` splits the 132-bit string into twelve 11-bit segments.

5. **Convert Parts to Mnemonic Words**:
   - `convert_parts_to_words()` reads a BIP-39-compatible word list (`word_list.txt`) to convert 11-bit segments into words.

6. **Derive Seed from Mnemonic**:
   - `mnemonic_to_seed()` derives a seed from the mnemonic using PBKDF2-HMAC-SHA512, which is crucial for deterministic key generation.

7. **Master Key and Chain Code Derivation**:
   - `derive_master_key_and_chain_code()` uses HMAC-SHA512 to derive the master private key and chain code from the seed.

8. **Generate Master Public Key**:
   - `derive_master_public_key()` generates the corresponding master public key using the secp256k1 curve.

9. **Child Key Derivation**:
   - `derive_child_key()` and `derive_child_key_at_index()` support BIP-32-like hierarchical key derivation for both hardened and non-hardened child keys.

### main.py

This script provides a PyQt5 GUI for user interaction with the wallet.

#### Main Components

- **Generate Wallet Button**: Users can generate a new wallet by clicking "Generate Wallet". The wallet consists of entropy, mnemonic, master key, chain code, and a testnet address.
- **Address Display**: Displays the generated Bitcoin testnet address.
- **Balance Display and Refresh**: The wallet balance is shown and can be updated using the "Refresh Balance" button, which uses `get_testnet_balance()`.
- **Send Funds**: Allows users to send Bitcoin from their generated testnet address to another address. The function `send_testnet_transaction()` is used to broadcast the transaction.
- **View Keys**: Displays the mnemonic phrase, master keys, child keys, and associated addresses.

#### GUI Implementation Details

- The `BitcoinKeyGenerator` class manages the UI and wallet generation process.
- The wallet generation flow involves invoking functions from `key_generation.py` to derive entropy, create a mnemonic, derive keys, and finally create a Bitcoin testnet address.
- `QPushButton`, `QLineEdit`, and `QTextEdit` components are utilized to provide interaction points for wallet generation, viewing, and transactions.

## Dependencies

- **Python 3.7+**
- **bit**: Bitcoin library for address generation and interaction (`pip install bit`)
- **ecdsa**: Elliptic curve operations (`pip install ecdsa`)
- **PyQt5**: GUI framework for Python (`pip install PyQt5`)

## Setting Up the Environment

Clone the repository:

```bash
git clone https://github.com/ptPierre/btcwallet.git
cd btcwallet
pip install -r requirements.txt
python main.py
```

## Important Notes
Wordlist: The word list used for mnemonic generation is expected to be in a file named word_list.txt. This file should be compatible with the BIP-39 standard (2048 words).
Testnet Only: The wallet and associated functions (private_key_to_testnet_address(), get_testnet_balance(), send_testnet_transaction()) are specifically designed for the Bitcoin testnet. They should not be used for mainnet Bitcoin transactions without proper modifications.
Security: Ensure that private keys and mnemonic phrases are securely stored. This code is designed for educational purposes and is not production-ready.

## License
This project is licensed under the MIT License.

## Acknowledgements
The implementation references BIP-32, BIP-39 standards.
The bit library is used for key management and testnet transactions.
