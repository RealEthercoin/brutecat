import hashlib
import bip39
import bip32
from buidl.ecc import PrivateKey
from buidl.helper import big_endian_to_int
from multiprocessing import Pool, cpu_count, Manager
import logging
from tqdm import tqdm

def WIF(address_hex):
    """Generate Wallet Import Format from a private key."""
    PK1 = '80' + address_hex
    PK2 = hashlib.sha256(codecs.decode(PK1, 'hex')).digest()
    PK3 = hashlib.sha256(PK2).digest()
    checksum = codecs.encode(PK3, 'hex')[0:8]
    PK4 = PK1 + checksum.decode()

    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    b58_string = ''
    address_int = int(PK4, 16)

    while address_int > 0:
        digit = address_int % 58
        digit_char = alphabet[digit]
        b58_string = digit_char + b58_string
        address_int //= 58

    return b58_string


def make_data_url(filename):
    """Convert an image to a Base64 string."""
    with open(filename, 'rb') as f:
        contents = f.read()
    return base64.b64encode(contents)


def generate_mnemonic(image_file):
    """Generate a BIP39 mnemonic from an image."""
    b64_s = make_data_url(image_file)
    entropy = hashlib.sha256(b64_s).digest()
    return bip39.encode_bytes(entropy)


def derive_address(mnemonic, passphrase):
    """Derive the SegWit (P2WPKH) address from the mnemonic and passphrase."""
    seed = bip39.phrase_to_seed(mnemonic, passphrase.strip())
    root = bip32.BIP32.from_seed(seed)
    private_key = PrivateKey(secret=big_endian_to_int(root.get_privkey_from_path("m/84'/0'/0'/0/0")))
    return private_key.point.p2wpkh_address()


def process_passphrase(passphrase, mnemonic, target_address, found_flag):
    """Test a single passphrase to see if it matches the target address."""
    if found_flag.value:  # Stop if already found
        return False

    address = derive_address(mnemonic, passphrase)
    logging.info(f"Testing passphrase: {passphrase.strip()} -> Address: {address}")

    if address == target_address:
        with open('found.txt', 'a') as result:
            result.write(f'{passphrase.strip()}|{address}\n')
        logging.info(f"Passphrase found: {passphrase.strip()}")
        found_flag.value = True
        return True

    return False


def worker(args):
    """Wrapper for multiprocessing."""
    passphrase, mnemonic, target_address, found_flag = args
    return process_passphrase(passphrase, mnemonic, target_address, found_flag)


def main():
    # Logging setup
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")

    # Constants
    entropy = "1808d35318ac7cb98b69ff9779b699d6a631f15e0b353ac89b7c4020774832ed"
    target_address = "bc1qcyrndzgy036f6ax370g8zyvlw86ulawgt0246r"

    # Generate mnemonic from entropy
    mnemonic = bip39.encode_bytes(bytes.fromhex(entropy))
    logging.info(f"Generated mnemonic: {mnemonic}")

    # Use a manager to share the found flag across processes
    manager = Manager()
    found_flag = manager.Value('b', False)

    try:
        with open("rockyou.txt", "r", encoding="utf-8", errors="ignore") as f:
            passphrases = f.readlines()
        
        # Load custom passphrases
        custom_passphrases = []
        try:
            with open("pass_list.txt", "r", encoding="utf-8", errors="ignore") as custom_file:
                custom_passphrases = custom_file.readlines()
                logging.info(f"Loaded {len(custom_passphrases)} custom passphrases from pass_list.txt")
        except FileNotFoundError:
            logging.warning("pass_list.txt not found. Proceeding without custom passphrases.")

        # Combine passphrases
        all_passphrases = list(custom_passphrases) + list(passphrases)
        logging.info(f"Total passphrases to test: {len(all_passphrases)}")

        # Use multiprocessing to process passwords
        with Pool(cpu_count()) as pool:
            args = ((passphrase, mnemonic, target_address, found_flag) for passphrase in all_passphrases)
            for _ in tqdm(pool.imap_unordered(worker, args), total=len(all_passphrases), desc="Progress"):
                if found_flag.value:
                    pool.terminate()
                    break

        # Check if a passphrase was successful
        if found_flag.value:
            logging.info("\nPassphrase found! Check found.txt for details.")
        else:
            logging.info("\nNo matching passphrase found.")
    except FileNotFoundError:
        logging.error("Error: rockyou.txt not found.")


if __name__ == "__main__":
    main()
