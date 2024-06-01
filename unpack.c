#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdbool.h>
#include <openssl/sha.h>
#include "AES_128_ECB.h"
#include <time.h>

#define CHUNK_SIZE 65536

typedef struct {
	uint32_t encrypted;
	uint32_t magic;
	uint32_t version;
	uint64_t offset;
	uint64_t size;
	uint8_t hash[20];
} __attribute__((packed)) FileHeader;


// Global variable to track current index offset during reading
uint64_t current_index_offset = 0;

// Function to read data from the index
void read_data(void *destination, const uint8_t *source, size_t length) {
	memcpy(destination, source + current_index_offset, length);
	current_index_offset += length;
}

void DecryptData(uint8_t *data, uint32_t size, const uint8_t *key) {
	AES_CTX ctx;
	AES_DecryptInit(&ctx, key);
	
	for (uint32_t offset = 0; offset < size; offset += 16) {
		AES_Decrypt(&ctx, data + offset, data + offset);
	}
	
	AES_CTX_Free(&ctx);
}

void XorEncryptDecrypt(uint8_t *data, uint32_t size) {
	for (uint32_t index = 0; index < size; index++) {
		data[index] ^= 0x79U;
	}
}

int create_file(const char *fullPath) {
	const char *lastSlash = strrchr(fullPath, '/');
	if (lastSlash != NULL) {
		size_t length = (size_t)(lastSlash - fullPath);
		char path[length + 1];
		strncpy(path, fullPath, length);
		path[length] = '\0';
		char *token = strtok(path, "/");
		char currentPath[1024] = "";
		while (token != NULL) {
			strcat(currentPath, token);
			strcat(currentPath, "/");
			mkdir(currentPath, 0777);
			token = strtok(NULL, "/");
		}
	}
	return open(fullPath, O_WRONLY | O_CREAT | O_TRUNC, 0644); 
}

char *base_name(const char *path) {
    // Find the last occurrence of '/'
    const char *last_slash = strrchr(path, '/');
    
    // If no '/' is found, the whole path is the filename
    if (last_slash == NULL) {
        return (char *)path;
    } else {
        // Otherwise, return the substring after the last '/'
        return (char *)(last_slash + 1);
    }
}

int main(int argc, const char *argv[]) {
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <file.pack>\n", argv[0]);
		return 1;
	}
	
	clock_t start = clock();
	
	if (access(argv[1], F_OK) == -1) {
		fprintf(stderr, "Input %s file does not exist.\n", argv[1]);
		return 1;
	}
	
	FileHeader info;
	uint8_t key[16];
	memset(key, 0x79, 16);
	
	int pack = open(argv[1], O_RDONLY);
	
	if (pack == -1) {
		fprintf(stderr, "Can't open input file!\n");
		return 1;
	}
	
	if (lseek(pack, -sizeof(FileHeader), SEEK_END) == -1) {
		printf("failed to seek file position\n");
		return 1;
	}
	
	if (read(pack, &info, sizeof(FileHeader)) != sizeof(FileHeader)) {
		printf("failed to read pack header\n");
		return 1;
	}
	
	if (info.version != 1) {
		fprintf(stderr, "This pack version unsupported!\n");
		close(pack);
		return 1;
	}
	
	if (info.size > 52428800) {
		fprintf(stderr, "Index data size is not compatible.\n");
		close(pack);
		return 1;
	}
	
	uint8_t *IndexData = (uint8_t*)malloc(info.size);
	
	if (!IndexData) {
		fprintf(stderr, "Memory allocation failed.\n");
		close(pack);
		return 1;
	}
	
	if (pread(pack, IndexData, info.size, info.offset) != info.size) {
		fprintf(stderr, "Failed to load index data\n");
		return 1;
	}
	
	if (info.encrypted) {
		DecryptData(IndexData, info.size, key);
	}
	
	uint8_t hash[20];
	
	SHA1(IndexData, info.size, hash);
	
	if (memcmp(info.hash, hash, 20) != 0) {
		fprintf(stderr, "corrupt pack index, mismatch (CRC)!\n");
		return 1;
	}
	
	uint32_t MountPointLength;
	char MountPoint[1024];
	int NumOfEntry;
	int32_t FilenameSize;
	char Filename[1024];
	uint8_t FileHash[20];
	uint64_t FileOffset = 0;
	uint64_t FileSize = 0;
	uint8_t Dummy[21];
	uint8_t Encrypted;
	
	uint8_t chunk[CHUNK_SIZE];
	
	read_data(&MountPointLength, IndexData, 4);
	read_data(MountPoint, IndexData, MountPointLength);
	read_data(&NumOfEntry, IndexData, 4);
	
	if (MountPointLength > 10) {
		memmove(MountPoint, MountPoint + 9, MountPointLength - 9);
        // Null-terminate the new string
        MountPoint[MountPointLength - 9] = '\0';
	}
	
	char filepath[4096];
	
	for (uint32_t Files = 0; Files < NumOfEntry; Files++) {
		read_data(&FilenameSize, IndexData, 4);
		read_data(Filename, IndexData, FilenameSize);
		read_data(FileHash, IndexData, 20);
		read_data(&FileOffset, IndexData, 8);
		read_data(&FileSize, IndexData, 8);
		read_data(&Encrypted, IndexData, 1);
		
		if (MountPointLength > 10) {
			memcpy(filepath, MountPoint, strlen(MountPoint));
			memcpy(filepath + strlen(MountPoint), Filename, strlen(Filename) + 1);
		} else {
			memcpy(filepath, Filename, strlen(Filename) + 1);
		}
		
		int out = create_file(filepath);
		
		if (out == -1) {
			fprintf(stderr, "Can't open output file %s\n", Filename);
			remove(Filename);
			continue;
		}
		
		lseek(pack, FileOffset, SEEK_SET);
		
		uint64_t originalFileSize = FileSize;
        uint64_t paddedFileSize = FileSize + (FileSize % AES_BLOCK_SIZE == 0 ? 0 : (AES_BLOCK_SIZE - (FileSize % AES_BLOCK_SIZE)));

		SHA_CTX sha_ctx;
        SHA1_Init(&sha_ctx);
		
		while (paddedFileSize > 0) {
            size_t bytesToRead = paddedFileSize < CHUNK_SIZE ? paddedFileSize : CHUNK_SIZE;

            if (read(pack, chunk, bytesToRead) != bytesToRead) {
                fprintf(stderr, "failed to read chunk!\n");
                close(out);
                free(IndexData);
                close(pack);
                return 1;
            }
            
            if (Encrypted == 1) {
                DecryptData(chunk, bytesToRead, key);
            } else if (Encrypted == 2) {
            	XorEncryptDecrypt(chunk, bytesToRead);
            }

            size_t bytesToWrite = originalFileSize < bytesToRead ? originalFileSize : bytesToRead;
            write(out, chunk, bytesToWrite);
            originalFileSize -= bytesToWrite;

            SHA1_Update(&sha_ctx, chunk, bytesToWrite);

            paddedFileSize -= bytesToRead;
        }
		
		SHA1_Final(hash, &sha_ctx);
		
		if (memcmp(hash, FileHash, 20) != 0) {
			printf("file %s is corrupted mismatch (CRC).\n", base_name(Filename));
			sleep(5);
		} else {
			printf("extracted: %s\n", base_name(Filename));
		}
		
		close(out);
	}
	
	free(IndexData);
	close(pack);
	
	clock_t end = clock();
	double cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
	printf("total files extracted %u from %s in %f seconds\n", NumOfEntry, argv[1], cpu_time_used);
    return 0;
}
