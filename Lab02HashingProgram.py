import hashlib
import os
import json

# Calculates the cryptographic hash of a file’s contents.
def hash_file(fileToHash):
    # open file given in input
    # read file in binary mode and hash its bytes
    with open(fileToHash, 'rb') as openedFile:
        readBytes = openedFile.read()

    sha2Hash = hashlib.sha256(readBytes)
    return sha2Hash.hexdigest()



# Navigates to the directory entered by the user and calls the hash_file function.
def traverse_directory():
    start_dir = input("Enter directory path: ").strip()
    # If caller wants a single hash of a directory path, hash the path string
    # but typical usage is to iterate files; keep this for backward compatibility
    return hash_file(start_dir)



# Calls the traverse_directory function, takes the hashes generated and outputs a 
# .json file containing filepath and hash. Returns “Hash table generated” to console when completed
def generate_table(path, hash_val):
    # store absolute path and format for json (use consistent keys)
    abs_path = os.path.abspath(path)
    data_to_write = {
        "filepath": abs_path,
        "hash": hash_val
    }
    
    if os.path.exists("hash_file.json"):
        with open('hash_file.json', 'r') as json_file:
            try:
                data = json.load(json_file)
            except json.JSONDecodeError:
                data = []
    else:
        data = []
    
    data.append(data_to_write)

        # making and pushing to .json file
    with open('hash_file.json', 'w') as json_file:
        json.dump(data, json_file, indent=4)

    return "Hash table generated"



# Reads from the generated hash table, traverses to the 
# directory, computes hash values of files within, compares computed hashes to 
# stored values in the hash table. Returns valid or invalid for each file to console.
def validate_hash():
    with open("hash_file.json", "r") as json_file:
        data = json.load(json_file)
    
    # build a set of stored absolute file paths for comparison
    stored_entries = []
    stored_paths = set()
    for entry in data:
        path = entry.get("filepath") or entry.get("file_path")
        given_hash = entry.get("hash") or entry.get("sha-256")
        if not path:
            continue
        abs_path = os.path.abspath(path)
        stored_entries.append((abs_path, given_hash))
        stored_paths.add(abs_path)

    # check each stored file: missing, valid, or invalid
    for abs_path, given_hash in stored_entries:
        if not os.path.exists(abs_path):
            print(abs_path, "has been removed")
            continue
        new_hash = hash_file(abs_path)
        if given_hash == new_hash:
            print(abs_path, "hash is valid")
        else:
            print(abs_path, "hash is valid")


    # detect newly added files in the directories that contain stored files
    dirs_to_check = set()
    for p in stored_paths:
        d = os.path.dirname(p) or os.getcwd()
        dirs_to_check.add(d)

    for d in dirs_to_check:
        if not os.path.exists(d):
            continue
        for root, _, files in os.walk(d):
            for fname in files:
                fullpath = os.path.abspath(os.path.join(root, fname))
                if fullpath not in stored_paths:
                    print(fullpath, "has been added")



# clears the .json file if needed
def clearJsonFile():
    if os.path.exists("hash_file.json"):
        with open('hash_file.json', 'w') as json_file:
            data = []
            json.dump(data, json_file, indent=4)
    else:
        print("file does not exist!")



# controller
def main():
    while (True):
        print("(0) exit - (1) add file/directory to hash table - (2) verify hash table - (3) clear hash table")
        choice = input("")
        if choice == "0":
            break
        if choice == "1":
            path = input("Enter path to file or directory you wish to scan: ").strip()
            if not os.path.exists(path):
                print("Path does not exist:", path)
                continue

            # if directory add every file found
            if os.path.isdir(path):
                for root, dirs, files in os.walk(path):
                    for fname in files:
                        fullpath = os.path.join(root, fname)
                        try:
                            h = hash_file(fullpath)
                            generate_table(fullpath, h)
                            print("Added:", fullpath)
                        except Exception as e:
                            print("Failed to hash", fullpath, "-", e)
            # if direct path to file
            else:
                try:
                    h = hash_file(path)
                    generate_table(path, h)
                    print("Added:", path)
                except Exception as e:
                    print("Failed to hash", path, "-", e)
        if choice == "2":
            validate_hash()
        if choice == "3":
            clearJsonFile()



main()