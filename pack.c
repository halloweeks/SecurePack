#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdbool.h>
#include "sha1.h"
#include "AES_128_ECB.h"
#include <time.h>

typedef struct {
    char *filename;
} Files;

void listFilesRecursively(const char *basePath, Files **files, int *count);

void add_files(const char *path, Files **files, int *count) {
    struct stat path_stat;
    stat(path, &path_stat);

    if (S_ISREG(path_stat.st_mode)) {
        // Add file to the structure
        (*files)[*count].filename = strdup(path);
        (*count)++;
        *files = realloc(*files, (*count + 1) * sizeof(Files));
    } else if (S_ISDIR(path_stat.st_mode)) {
        // Recursively add files from the directory
        listFilesRecursively(path, files, count);
    }
}

void listFilesRecursively(const char *basePath, Files **files, int *count) {
    char path[1000];
    struct dirent *dp;
    DIR *dir = opendir(basePath);

    if (!dir) {
        return;
    }

    while ((dp = readdir(dir)) != NULL) {
        if (strcmp(dp->d_name, ".") != 0 && strcmp(dp->d_name, "..") != 0) {
            // Construct full path
            sprintf(path, "%s/%s", basePath, dp->d_name);
            add_files(path, files, count);
        }
    }

    closedir(dir);
}

typedef struct {
	uint32_t encrypted;
	uint32_t magic;
	uint32_t version;
	uint64_t offset;
	uint64_t size;
	uint8_t hash[20];
} __attribute__((packed)) FileHeader;

int64_t fsize(const char *filename) {
	struct stat st;
    if (stat(filename, &st) == 0)
        return st.st_size;
    else
        return -1; // Return -1 if file not found or other error occurs
}

#define CHUNK_SIZE 65536

uint64_t current_index_offset = 0;

void write_data(uint8_t *destination, const void *source, size_t length) {
	memcpy(destination + current_index_offset, source, length);
	current_index_offset += length;
}

void EncryptData(uint8_t *data, uint32_t size, const uint8_t *key) {
	AES_CTX ctx;
	AES_EncryptInit(&ctx, key);
	
	for (uint32_t offset = 0; offset < size; offset += 16) {
		AES_Encrypt(&ctx, data + offset, data + offset);
	}
}

void XorEncryptDecrypt(uint8_t *data, uint32_t size) {
	for (uint32_t index = 0; index < size; index++) {
		data[index] ^= 0x79U;
	}
}

int main(int argc, const char *argv[]) {
	if (argc < 3) {
        fprintf(stderr, "Usage: %s <output_file> <directory_or_file_path> [<directory_or_file_path> ...]\n", argv[0]);
        return 1;
    }
    
    clock_t start = clock();
    
    FileHeader info;
    info.encrypted = 0; // This will encrypt the index table (contains file information like filename, offset, size, hash, etc)
    info.magic = 0xA74E99D8;
    info.version = 1;
    
    uint8_t encrypt_all_files = 0; // It will encrypt all file contents (none=0, aes=1, xor=2)
    
    uint8_t key[16];
    memset(key, 0x79, 16);
    
    Files *files = malloc(sizeof(Files));
    int count = 0;
    
    for (int index = 2; index < argc; index++) {
        add_files(argv[index], &files, &count);
    }
    
    int pack = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC, 0664);
    
    if (pack == -1) {
    	fprintf(stderr, "Can't open output file!\n");
        return 1;
    }
    
    uint8_t chunk[CHUNK_SIZE + 16];
    
    off_t offset = 0;
    int len = -1;
    
    uint8_t *IndexData = (uint8_t*)malloc(1024 * 1024 * 50);
    
    if (!IndexData) {
    	fprintf(stderr, "memory allocation failed!\n");
        return 1;
    }
    
    // All files extracted into test folder because is base directory
    char MountPoint[] = "../../../test/";
    // All files extracted in current directory
    // char MountPoint[] = "../../../";
    // calculate mount point length
    uint32_t MountPointLength = strlen(MountPoint) + 1;
    
    write_data(IndexData, &MountPointLength, 4);
    write_data(IndexData, MountPoint, MountPointLength);
    write_data(IndexData, &count, 4);
    
    uint32_t FilenameSize = 0;
    uint64_t FileOffset = 0;
    uint64_t FileSize = 0;
    uint8_t FileHash[20];
    uint8_t Encrypted = encrypt_all_files;
    uint8_t FileEncryptedHash[20];
    
    for (int index = 0; index < count; index++) {
    	FileOffset = lseek(pack, 0, SEEK_CUR);
        
        int fd = open(files[index].filename, O_RDONLY);
        
        if (fd == -1) {
        	fprintf(stderr, "Can't open input file %s!\n", files[index].filename);
            return 0;
        }
        
        FilenameSize = strlen(files[index].filename) + 1;
        FileSize = fsize(files[index].filename);
        
        write_data(IndexData, &FilenameSize, 4);
        write_data(IndexData, files[index].filename, FilenameSize);
        
        SHA1_CTX ctx;
        SHA1_Init(&ctx);
        
        uint8_t padding_size = 0;
        
        while ((len = read(fd, chunk, CHUNK_SIZE)) > 0) {
        	SHA1_Update(&ctx, chunk, len);
        
            padding_size = (len % AES_BLOCK_SIZE == 0) ? 0 : AES_BLOCK_SIZE - (len % AES_BLOCK_SIZE);
            
            if (padding_size != 0) {
            	memset(chunk + len, padding_size, padding_size);
                len += padding_size;
            }
            
            if (encrypt_all_files == 1) {
            	EncryptData(chunk, len, key);
            } else if (encrypt_all_files == 2) {
                XorEncryptDecrypt(chunk, len);
            }
            
            write(pack, chunk, len);
        }
        
        SHA1_Final(&ctx, FileHash);
        
        write_data(IndexData, FileHash, 20);
        write_data(IndexData, &FileOffset, 8);
        write_data(IndexData, &FileSize, 8);
        write_data(IndexData, &Encrypted, 1);
        
        printf("added %s\n", files[index].filename);
    }
    
    // get current position
    info.offset = lseek(pack, 0, SEEK_CUR);
    // get total index size
    info.size = current_index_offset;
    // index data require padding
    uint8_t padding_size = (info.size % AES_BLOCK_SIZE == 0) ? 0 : AES_BLOCK_SIZE - (info.size % AES_BLOCK_SIZE);
    // if needed padding
    if (padding_size != 0) {
    	// add padding into index data
    	for (uint32_t index = info.size; index < info.size + padding_size; index++) {
    	    IndexData[index] = padding_size;
        }
        // update index size + padding_size
        info.size += padding_size;
    }
    
    // store index data sha into 'info.hash'
    SHA1(IndexData, info.size, info.hash);
    
    if (info.encrypted == 1) {
    	EncryptData(IndexData, info.size, key);
    } else if (info.encrypted == 2) {
    	XorEncryptDecrypt(IndexData, info.size);
    }
    
    // write index table into pack file
    write(pack, IndexData, info.size);
    // write pack header at end of pack file
    write(pack, &info, sizeof(info));
    
    // Free allocated memory
    for (int i = 0; i < count; i++) {
        free(files[i].filename);
    }
    free(files);
    
    clock_t end = clock();
	double cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
	printf("added %u files to %s in %f seconds\n", count, argv[1], cpu_time_used);
    return 0;
}
