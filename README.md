# Cryptfile
Cryptfile is a command-line utility for encrypting and decrypting files and directories using AES-256 encryption. It provides a secure way to protect your sensitive data by leveraging strong cryptographic algorithms AES-256.

# Features
- Encrypt and decrypt files & folders (directories) 
- Optional compression for encrypted directories
- Secure password hashing using SHA-256
- Removal of original files or directories after encryption or decryption


# Linux Installation
```
git clone https://github.com/FlareXes/cryptfile.git && cd cryptfile && ./setup
```

# Usage

> Note: `Cryptfile` doesn't follow symbolic links.

### Encrypt a File

To encrypt a file, use the following command:

```
cryptfile -e <file_path>
```

### Decrypt a File

To decrypt a file, use the following command:

```
cryptfile -d <encrypted_file_path>
```

### Encrypt a Directory

To encrypt a directory, use the following command:

```
cryptfile -ed <directory_path>
```

### Decrypt a Directory

To decrypt a directory, use the following command:

```
cryptfile -dd <encrypted_directory_path>
```

### Options

- `-r, --remove`: Delete original files or directories after encryption or decryption.
- `-c, --compress`: Compress directory for smaller encrypted file (slows down process).
- `-h, --help`: Show the help message and exit.

## Warning

- Ensure that you remember your password used for encryption, as it cannot be recovered if lost.

---

# Licence 
This work by [FlareXes](https://github.com/FlareXes) is Licenced Under [GNU GPLv3](LICENCE)
