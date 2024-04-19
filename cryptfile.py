import argparse
import os
import pickle
import sys
from dataclasses import dataclass, astuple
from getpass import getpass
from shutil import make_archive, unpack_archive, rmtree
from typing import Set

from Cryptodome.Cipher import AES
from Cryptodome.Hash.SHA256 import SHA256Hash
from Cryptodome.Protocol.KDF import scrypt
from Cryptodome.Random import get_random_bytes


class Template:
    @dataclass
    class CipherConfig:
        """A data class for storing ciphertext, salt, tag, and nonce."""

        ciphertext: bytes
        salt: bytes
        tag: bytes
        nonce: bytes
        filename: str = ""


class Utils:
    """A class that provides utility functions."""

    @staticmethod
    def attrs(cc):
        """Returns a tuple of the attributes of a CipherConfig object.

        :param cc: A CipherConfig object
        :type cc: CipherConfig
        :returns: A tuple of the attributes of the CipherConfig object
        :rtype: tuple
        """

        return astuple(cc)

    @staticmethod
    def _rename(file):
        """Renames a file by removing the '.enc' extension if parameter 'file' endswith '.enc'
        or by appending the '.cryptfile' extension if parameter 'file' does not endswith '.enc'.

        :param file: The file to be renamed
        :type file: str
        :returns: The renamed file
        :rtype: str
        """

        if file.endswith(".enc"):
            return file[:-4]
        else:
            print("[*] It seems you have changed filename after encryption.")
            print(f"[*] Decrypted file will be saved as `{file + '.cryptfile'}`.")
            return file + ".cryptfile"

    @staticmethod
    def save_cc(data, file):
        """Saves CipherConfig in pickled format to a file.

        :param data: The data to be saved
        :type data: CipherConfig
        :param file: The file to save the data to
        :type: file: str
        """

        with open(file + ".enc", "wb") as f:
            pickle.dump(data.__dict__, f, -1)

    @staticmethod
    def save_file(data, filename):
        """Saves data to a file.

        :param data: The data to be saved
        :type data: bytes
        :param filename: The file to save the data to
        :type: filename: str
        """

        with open(filename, "wb") as f:
            f.write(data)

    @staticmethod
    def open_file(file, pickled: bool = False):
        """Opens a file and returns its content in either bytes or pickled format.

        :param file: The file to be opened
        :type file: str
        :param pickled: Specifies whether file content is pickled or not. Defaults to False
        :type pickled: bool, optional

        :returns: The content of the file in either bytes or pickled format, depending on the value
            of the 'pickled' argument.
        :rtype: bytes or object
        """

        with open(file, "rb") as f:
            if pickled:
                data_dict = pickle.load(f)
                data = Template.CipherConfig(**data_dict)
            else:
                data = f.read()
        return data

    @staticmethod
    def archive_dir(directory, compress=False):
        if compress:
            archive_filename = os.path.basename(directory)
            output_path = make_archive(archive_filename, "zip", directory)
        else:
            archive_filename = os.path.basename(directory)
            output_path = make_archive(archive_filename, "tar", directory)
        return output_path

    @staticmethod
    def unarchive_dir(archive_file):
        if "tar" in archive_file:
            archive_filename = archive_file.split(".tar")[0]
        else:
            archive_filename = archive_file.split(".zip")[0]

        unpack_archive(archive_file, extract_dir=archive_filename)


class Security:
    """Class for handling all cryptographical functions."""

    def __init__(self, master_password_hash: bytes):
        """
        Initialize the object with the given master password hash.

        :param master_password_hash: The master password hash
        :type master_password_hash: bytes
        """

        self.mp = master_password_hash
        # Setting cost factor for the key derivation function
        self.cost_factor = 2**20
        self.rounds = 8
        self.parallel_factor = 1
        self.key_length = 32

    @staticmethod
    def getpass(no_check: bool = False):
        """
        Hash the passwords entered by the user and return a hashed password if `no_check` is True,
        else compare the two passwords  to confirm while encryption and return a hashed password if they match.

        :param no_check: If True, do not check for password matching. Defaults to False.
        :type no_check: bool
        :return: The hashed password
        :rtype: bytes
        """

        # Hash the passwords entered by the user
        p1 = SHA256Hash(getpass("Enter Password: ").encode("utf-8")).hexdigest()
        if no_check:
            return p1.encode("utf-8")
        p2 = SHA256Hash(getpass("Re-enter Password: ").encode("utf-8")).hexdigest()

        if p1 == p2:
            return p1.encode("utf-8")
        else:
            print(">>> Incorrect Password ! <<<")
            sys.exit(1)

    def _kdf_scrypt(self, _salt: bytes) -> bytes:
        """
        Use scrypt to derive a key from the master password hash and the given salt.

        :param _salt: The salt to use for key derivation
        :type _salt: bytes
        :returns: The derived key
        :rtype: bytes
        """

        return scrypt(
            str(self.mp),
            str(_salt),
            self.key_length,
            self.cost_factor,
            self.rounds,
            self.parallel_factor,
        )

    def encrypt(self, data: bytes):
        """
        Takes data to encrypt and use the key to encrypt the data. Return a CipherConfig object
        containing the encrypted data, salt, tag, and nonce.

        :param data: The data to encrypt
        :type data: bytes
        :returns: CipherConfig: The CipherConfig object containing the encrypted data, salt, tag, and nonce
        :rtype: CipherConfig
        """

        _salt = get_random_bytes(32)
        # Derive a key from the master password hash and the salt
        key = self._kdf_scrypt(_salt)
        # Initialize a cipher object with the key and the GCM mode
        cipher = AES.new(key, AES.MODE_GCM)
        # Encrypt the data
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return Template.CipherConfig(ciphertext, _salt, tag, cipher.nonce)

    def decrypt(self, cc):
        """
        Take CipherConfig object and derive a key from the master password hash and CipherConfig object, and use the key
        to decrypt and verify the data. Return the decrypted data as a string.

        :param cc: The CipherConfig object containing the encrypted data, salt, tag, and nonce
        :type cc: CipherConfig
        :returns: The decrypted data
        :rtype: bytes
        """

        # Extract the ciphertext, salt, tag, and nonce from the CipherConfig object
        ciphertext, _salt, tag, nonce, _ = Utils.attrs(cc)
        # Derive a key from the master password hash and the salt
        key = self._kdf_scrypt(_salt)
        # Initialize a cipher object with the key, the GCM mode, and the nonce
        cipher = AES.new(key, AES.MODE_GCM, nonce)
        # Decrypt and verify the data
        data = cipher.decrypt_and_verify(ciphertext, tag)
        return data


class Cryptfile:
    """Cryptfile class provides user interation functionality and prepare files for encryption and decryption."""

    def __init__(self, files: Set = None, directories: Set = None):
        """Initializes the Cryptfile object
        :param files: The file to be encrypted or decrypted
        :type files: set
        :param directories: The directory to be encrypted or decrypted
        :type directories: set
        """

        self.files = files
        self.directories = directories

    def encrypt_file(self):
        """
        Firstly, retrieve the file content in bytes format and then sent to the Security class for encryption.
        The encrypted content is then saved with the original filename + '.enc' extension.

        Example
        -------
        original file: example.txt
        after encryption: example.txt.enc
        """

        # get password hash
        password_hash = Security.getpass()

        for file in self.files:
            # Get file content in bytes format to encrypt
            data = Utils.open_file(file)
            print(f"\nEncrypting [ {file} ]", end="\r")

            cc = Security(password_hash).encrypt(data)
            cc.filename = file

            # Save encrypted content with original file and '.enc' extension
            Utils.save_cc(cc, file)
            print(f"Encrypting [ {file} ] \t [+] Completed", end="\n", flush=True)

    def decrypt_file(self):
        """
        The file content is first retrieved in picked bytes format and then decrypted using the Security class.
        The decrypted content is then saved with the original file name, either without the '.enc' extension
        or with the '.cryptfile' extension if any file is supplied for decryption without `.enc` extension.
        """

        # Get password hash
        password_hash = Security.getpass(no_check=True)

        for file in self.files:
            # Get file content in picked bytes format to decrypt
            cc = Utils.open_file(file, pickled=True)

            print(f"\nDecrypting [ {file} ]", end="\r")
            data = Security(password_hash).decrypt(cc)

            Utils.save_file(data, cc.filename)
            print(f"Decrypting [ {file} ] \t [+] Completed", end="\n", flush=True)

    def encrypt_dir(self, compress=False):
        archives_location = set()
        print(f"Archiving {self.directories}\n")
        for directory in self.directories:
            archives_location.add(Utils.archive_dir(directory, compress=compress))

        Cryptfile(files=archives_location).encrypt_file()

        # Remove archive_file after encryption
        print(f"Removing archived files...")
        set(map(lambda archive_file: os.remove(archive_file), archives_location))

    def decrypt_dir(self):
        archives_location = set()
        Cryptfile(self.files).decrypt_file()

        print(f"Extracting archived files {self.files}")
        for file in self.files:
            # extract archive_file after encryption
            archive_file = file.split(".enc")[0]
            Utils.unarchive_dir(archive_file)
            archives_location.add(archive_file)

        # Remove archive_file after encryption
        print(f"Removing archived files...")
        set(map(lambda archive_file: os.remove(archive_file), archives_location))


def process(args):
    # Start file encryption if variable `files` is not none
    files = args.encrypt
    if files is not None:
        Cryptfile(files=set(files)).encrypt_file()
        # delete file if `-r` is set
        if args.remove:
            set(map(lambda file: os.remove(file), files))

    # Start file decryption if variable `files` is not none
    files = args.decrypt
    if files is not None:
        Cryptfile(files=set(files)).decrypt_file()
        # delete file if `-r` is set
        if args.remove:
            set(map(lambda file: os.remove(file), files))

    # Start directory archiving and encryption if variable `directories` is not none
    directories = args.encrypt_dir
    if directories is not None:
        Cryptfile(directories=set(directories)).encrypt_dir(compress=args.compress)
        # delete directory if `-r` is set
        if args.remove:
            set(
                map(
                    lambda directory: rmtree(directory, ignore_errors=False),
                    directories,
                )
            )

    # Start directory archiving and encryption if variable `files` is not none
    files = args.decrypt_dir
    if files is not None:
        Cryptfile(files=set(files)).decrypt_dir()
        # delete directory if `-r` is set
        if args.remove:
            set(map(lambda file: os.remove(file), files))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="cryptfile",
        description="Command line utility to encrypt or decrypt the file with AES256.",
        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=47),
    )

    parser.add_argument(
        "-r",
        "--remove",
        action="store_true",
        help="delete original file or directory after encryption or decryption",
    )
    parser.add_argument(
        "-c"
        "--compress",
        action="store_true",
        help="delete original file or directory after encryption or decryption",
    )
    parser.add_argument(
        "-c",
        "--compress",
        action="store_true",
        help="compress directory for smaller encrypted file (slows down process)",
    )
    parser.add_argument(
        "-e", "--encrypt", nargs="+", type=str, help="encrypt the specified file"
    )
    parser.add_argument(
        "-d", "--decrypt", nargs="+", type=str, help="decrypt the specified file"
    )
    parser.add_argument(
        "-ed", "--encrypt-dir", nargs="+", type=str, help="encrypt directory"
    )
    parser.add_argument(
        "-dd", "--decrypt-dir", nargs="+", type=str, help="decrypt directory"
    )

    args = parser.parse_args()
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    process(args)
