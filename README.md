# SecurePack

SecurePack is a utility to pack and unpack files into a custom archive format. The `pack` utility allows you to bundle multiple files (including those in nested directories) into a single archive, while the `unpack` utility enables you to extract files from the archive. The archive format supports both AES-128 and XOR encryption to secure your files.

## Features

- Pack multiple files (including nested directories) into a single archive.
- Unpack files from the archive, preserving the directory structure.
- Supports AES-128 encryption for secure file storage.
- Supports XOR encryption as an alternative.
- Option to disable encryption entirely.
- Encrypts index data (file metadata) for added security.
- Automatically creates necessary directories during unpacking.
- Validates file integrity using SHA-1 hashes.

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/halloweeks/SecurePack.git
    cd SecurePack
    ```

2. Compile the source code:
    ```sh
    gcc -o pack pack.c -lssl -lcrypto
    gcc -o unpack unpack.c -lssl -lcrypto
    ```

## Usage

### Packing Files

To pack files into an archive, use the `pack` utility. You can choose between AES encryption, XOR encryption, or no encryption for file contents, and you can also choose to encrypt the index data:

```sh
./pack <output_archive> <file1> <file2> ...
```

You can also specify directories containing files to be packed. The utility will recursively find all files within the directories.

To specify the encryption method for files and whether to encrypt the index data, modify the relevant variables in `pack.c`:

- `encrypt_all_files` variable:
  - `0`: No encryption
  - `1`: AES-128 encryption
  - `2`: XOR encryption

- `info.encrypted` variable:
  - `0`: No encryption
  - `1`: AES-128 encryption
  - `2`: XOR Encryption

For example, to pack files with AES encryption for both files and index data:
```c
uint8_t encrypt_all_files = 1; // AES-128 encryption for files
info.encrypted = 0;         // No encryption for index data
```

Then run:
```sh
./pack main.pack example.txt
```

### Unpacking Files

To unpack files from an archive, use the `unpack` utility:

```sh
./unpack <input_archive>
```

For example:
```sh
./unpack main.pack
```

This command will extract the files from `main.pack` to the current directory, preserving the directory structure, and automatically creating necessary directories if they do not exist.

## Example

```sh
# Packing files with AES encryption
./pack main.pack example.txt

# Unpacking files
./unpack main.pack
```

## Notes

- Ensure that the directories and files you are packing exist and are readable.
- The unpacking utility will recreate the directory structure as it was during packing.
- For AES encryption, the encryption key is hardcoded in the source code as a 16-byte array of 0x79. You can modify this in the `pack.c` and `unpack.c` files.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.
