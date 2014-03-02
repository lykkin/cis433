#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gcrypt.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>

int main(int argc, char *argv[])
{

  //initialization taken from the man pages
  /* Version check should be the very first call because it
  makes sure that important subsystems are intialized. */
  if (!gcry_check_version (GCRYPT_VERSION))
  {
    fputs ("libgcrypt version mismatch\n", stderr);
    exit (2);
  }

  /* Disable secure memory.  */
  gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
    
  /* ... If required, other initialization goes here.  */
  /* Tell Libgcrypt that initialization has completed. */
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

  //variables and such
  char port[8];
  char fileName[100];
  char salt[17];
  char password[33];
  char key[33];
  int fileSpecified = 0; 
  struct addrinfo hints, *servinfo;
  int i;
  int s; //socket

  //parse input
  if(argc < 2 || argc > 3){
    printf("Incorrect syntax, should be: ./uodec [<port>]  [-l <file name>]");
    exit(1);
  }

  if(strncmp(argv[1], "-l", 2) == 0){
    fileSpecified = 1;
    strcpy(fileName, argv[2]);
  } else {
    memset(port, 0, 8);
    memcpy(port, argv[1], strlen(argv[1]));
  }

  FILE *srcFile;
  
  //followed beej's networking guide for this section: http://beej.us/guide/bgnet/output/html/singlepage/bgnet.html#syscalls
  if(!fileSpecified){
    int fileSocket;
    struct sockaddr_storage fileAddr;
    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;   
    hints.ai_family = AF_INET;
    getaddrinfo(NULL, port, &hints, &servinfo);
    s = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
    bind(s, servinfo->ai_addr, servinfo->ai_addrlen);
    listen(s, 20);
    socklen_t addr_size = sizeof fileAddr;
    printf("Waiting for connection...\n");
    fileSocket = accept(s, (struct sockaddr *) &fileAddr, &addr_size);
    printf("Inbound file.");
    shutdown(s, 2);
    char recvBuffer[512];
    recv(fileSocket, fileName, 100, 0);
    printf("name = %s\n", fileName);
    srcFile = fopen(fileName, "w");
    memset(recvBuffer, '\0', 512);
    int length;
    while(length = recv(fileSocket, recvBuffer, 512, 0)){
    printf("writing files, length %d\n", length);
      fwrite(recvBuffer, 1, length, srcFile);
    }
    close(fileSocket);
    fclose(srcFile);
  }

  srcFile = fopen(fileName, "r");
  char decFileName[100];
  memset(decFileName, 0, 100);
  strcpy(decFileName, fileName);
  decFileName[strlen(decFileName) - 3] = '\0';
  FILE * decFile = fopen(decFileName, "a+");
  if(fgetc(decFile) != EOF){
    printf("%s already exists, exitting.\n", decFileName);
    fclose(srcFile);
    fclose(decFile);
    exit(1);
  }

  //Get a password from the user
  printf("Password: ");
  for(i = 0; i < 33; i++){
    password[i] = '\0';
  }
  fgets(password, 32, stdin);


  //grab salt and generate key
  fread(salt, 1, 16, srcFile);
  salt[16] = '\0';
  gpg_error_t err = gcry_kdf_derive(password, strlen(password), GCRY_KDF_PBKDF2, GCRY_MD_SHA256, salt, strlen(salt), 3000, 32, key);
  key[32] = '\0';

  //initialize all the cipher stuff
  gcry_cipher_hd_t cipher;
  gcry_md_hd_t hash;
  err = gcry_cipher_open(&cipher, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0);
  err = gcry_cipher_setkey(cipher, key, 32);
  err = gcry_cipher_setiv(cipher, salt, 16);
  err = gcry_md_open(&hash, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);
  err = gcry_md_setkey(hash, key, 32);
  char curBlock[1056];
  int readlen;
  int padding = 0;
  char message[1024];
  char hmac[32];
  int totalSize = 0;

  //file parsing below
  while(!feof(srcFile)){
    memset(curBlock, 0, 1056);
    readlen = fread(curBlock, 1, 1056, srcFile);
    if(readlen < 1056){
      padding = ((int) curBlock[readlen-1]);
      readlen -= 1;
    }
    gcry_cipher_decrypt(cipher, curBlock, readlen, NULL, 0);
    memcpy(message, curBlock, 1024);
    memcpy(hmac, curBlock + 1024, 32);
    readlen -= 32;
    readlen -= padding;
    totalSize += readlen;
    printf("read %d bytes, wrote %d bytes,\n", readlen + 32 + padding + 1, readlen);
    readlen = fwrite(message, 1, readlen, decFile);
  }

  if(fileSpecified){
    printf("Successfully decrypted %s to %s (%d bytes written).\n", fileName, decFileName, totalSize);
  } else {
    printf("Successfully recieved and decrypted %s to %s (%d bytes written).\n", fileName, decFileName, totalSize);
  
  }

  //house keeping
  fclose(srcFile);
  fclose(decFile);
  gcry_cipher_close(cipher);
  gcry_md_close(hash);
  
  return 0;
}
