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

  char port[8];
  char fileName[100];
  char salt[17];
  char password[33];
  char key[33];
  int fileSpecified = 0; 
  struct addrinfo hints, *servinfo;
  int i;
  int s; 
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
  
  if(fileSpecified){
  printf("%s\n",fileName);
    srcFile = fopen(fileName, "r");
  } else {
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
      printf("CONNECTED\n");
      
    //sockets go here. 
  }
  char decFileName[100];
  strcpy(decFileName, fileName);
  decFileName[strlen(decFileName) - 1] = '\0';
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
  //generate a salt and key
  fread(salt, 1, 16, srcFile);
  salt[16] = '\0';
  gpg_error_t err = gcry_kdf_derive(password, strlen(password), GCRY_KDF_PBKDF2, GCRY_MD_SHA256, salt, strlen(salt), 100, 32, key);
  key[32] = '\0';
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
  while(!feof(srcFile)){
    for(i = 0; i <1056; i++){
      curBlock[i] = 0;
    }
    readlen = fread(curBlock, 1, 1056, srcFile);
    gcry_cipher_decrypt(cipher, curBlock, readlen, NULL, 0);
    memcpy(message, curBlock, 1024);
    memcpy(hmac, curBlock + 1024, 32);
    readlen -= 32;
    if(readlen != 1024){
      for(i = 0; i < readlen; i++){
        if(curBlock[i] == 0){
          if(++padding == 15){
            break;
          };
        }
      }
    }
    readlen -= padding;
    totalSize += readlen;
    printf("read %d bytes, wrote %d bytes,\n", readlen + 32 + padding, readlen);
    readlen = fwrite(curBlock, 1, readlen - padding, decFile);
  }
  if(fileSpecified){
    printf("Successfully decrypted %s to %s (%d bytes written).\n", fileName, decFileName, totalSize);
  } else {
    printf("Successfully recieved and decrypted %s to %s (%d bytes written).\n", fileName, decFileName, totalSize);
  
  }
  fclose(srcFile);
  fclose(decFile);
  gcry_cipher_close(cipher);
  gcry_md_close(hash);
  
  return 0;
}
