# -File-Hashing-Utility
#The script computes cryptographic hash values (MD5, SHA-1, SHA-256) for a given file. Hash values are commonly used in digital forensics to verify file #integrity and compare files during investigations.

import hashlib
import os

def compute_file_hash(file_path, hash_algorithm='sha256'):
    # Supported hash algorithms: md5, sha1, sha256
    if not os.path.isfile(file_path):
        print(f"File {file_path} does not exist.")
        return
    
    hash_func = None
    if hash_algorithm == 'md5':
        hash_func = hashlib.md5()
    elif hash_algorithm == 'sha1':
        hash_func = hashlib.sha1()
    elif hash_algorithm == 'sha256':
        hash_func = hashlib.sha256()
    else:
        print(f"Unsupported hash algorithm: {hash_algorithm}")
        return
    
    # Open file in binary mode
    with open(file_path, 'rb') as file:
        # Read file in chunks of 4K for memory efficiency
        while chunk := file.read(4096):
            hash_func.update(chunk)

    return hash_func.hexdigest()

def main():
    file_path = input("Enter the path of the file to hash: ")
    hash_algorithm = input("Enter the hash algorithm (md5, sha1, sha256): ").lower()

    hash_value = compute_file_hash(file_path, hash_algorithm)
    if hash_value:
        print(f"\n{hash_algorithm.upper()} Hash of {file_path}:")
        print(hash_value)

if __name__ == "__main__":
    main()

