#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gcrypt.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>

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

  int local = 1;
  char address[17];
  char port[8];
  char fileName[100];
  int fileSpecified = 0;
  char salt[17];
  char password[33];
  char key[33];
  int s; //socket
  struct addrinfo *servinfo, hints;
  
  if(argc > 4){
    printf("Incorrect syntax, should be: ./uoenc <input file> [-d <output IP-addr:port>] [-l]");
    exit(1);
  }
  int i;
  for(i = 1; i < argc; i++){
    if(strncmp(argv[i], "-l", 2) == 0){
       local = 1;
    }
    
    //grab ip and port if specified
    else if(strncmp(argv[i], "-d", 2) == 0){
      local = 0;
      i++;
      int j;
      for(j = 0; j <= 16; j++){
        address[j] = argv[i][j];
        if(argv[i][j] == ':'){
          address[j] = '\0';
          memset(port, 0, 8);
          memcpy (port, argv[i] + j + 1, strlen(argv[i]) - j - 1);
          break;
        }
      }
    }

    else {
      fileSpecified = 1;
      strncpy (fileName, argv[i], strlen(argv[i]));
      fileName[strlen(argv[i])] = '\0';
    }

  }
  
  //start file parsing
  FILE *srcFile = fopen(fileName, "r");

  if(fileSpecified && srcFile){
    char encFileName[100];
    strcpy(encFileName, fileName);
    strcat(encFileName, ".uo");
    FILE * encFile = fopen(encFileName, "a+");

    if(fgetc(encFile) != EOF){ //check if target encrypt file is empty
      printf("%s already exists, exitting.\n", encFileName);
      fclose(srcFile);
      fclose(encFile);
      exit(1);
    }

    //Get a password from the user
    printf("Password: ");
    for(i = 0; i < 33; i++){
      password[i] = '\0';
    }
    fgets(password, 32, stdin);

    //generate a salt and key
    gcry_randomize(salt, 16, GCRY_STRONG_RANDOM);
    salt[16] = '\0';
    gpg_error_t err = gcry_kdf_derive(password, strlen(password), GCRY_KDF_PBKDF2, GCRY_MD_SHA256, salt, strlen(salt), 3000, 32, key);
    key[32] = '\0';

    //place salt at the beginning of the file to retrieve on the other side
    fputs(salt, encFile);

    //set-up/declare all cipher stuff
    gcry_cipher_hd_t cipher;
    gcry_md_hd_t hash;
    err = gcry_cipher_open(&cipher, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0);
    err = gcry_cipher_setkey(cipher, key, 32);
    err = gcry_cipher_setiv(cipher, salt, 16);
    err = gcry_md_open(&hash, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);
    err = gcry_md_setkey(hash, key, 32);
    char curBlock[1056];
    int readlen;
    int padding;
    int padded = 0;
    char paddingChar = 0;
    int totalSize = 16; //16 since salt is already written

    //start encrypt/writing
    while(!feof(srcFile)){
      memset(curBlock, 0, 1056);
      readlen = fread(curBlock, 1, 1024, srcFile);

      //if we have hit the end, pad the rest of the 16-byte block and flag as padded
      if(readlen < 1024){
        padding = readlen % 16 ? 16 - (readlen % 16) : 0;
        readlen += padding;
        paddingChar = (char) padding;
        padded = 1;
        totalSize += 1;
      }

      //include hash for the current block and encrypt
      gcry_md_write(hash, curBlock, readlen);
      memcpy(curBlock + readlen, gcry_md_read(hash, GCRY_MD_SHA256), 32);
      readlen += 32;
      printf("read %d bytes, wrote %d bytes,\n", readlen - 32 - padding,  readlen + 1);
      totalSize += readlen;
      gcry_cipher_encrypt(cipher, curBlock, readlen, NULL, 0);
      if(padded){
        curBlock[readlen] = paddingChar;
      }
      readlen = fwrite(curBlock, 1, readlen + padded, encFile);
    }

    printf("Successfully encrypted %s to %s (%d bytes written).\n", fileName, encFileName, totalSize);

    //if this is to be sent over a socket, do so
    if(!local){
      //followed beej's networking guide for this section: http://beej.us/guide/bgnet/output/html/singlepage/bgnet.html#syscalls
      printf("Transmitting to %s:%s\n",address,port);
      memset(&hints, 0, sizeof hints);
      hints.ai_socktype = SOCK_STREAM;
      hints.ai_family = AF_INET;
      getaddrinfo(address, port, &hints, &servinfo);
      s = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
      connect(s, servinfo->ai_addr, servinfo->ai_addrlen);
      fseek(encFile, 0, SEEK_SET);
      send(s, encFileName, strlen(encFileName),0);
      char sendBuffer[512];
      int length;
      while(!feof(encFile)){
        length = fread(sendBuffer, 1, 512, encFile);
        send(s, sendBuffer, length, 0);
      }
      close(s);
      printf("Successfully received.\n");
    } 

    //close all handles we had
    fclose(srcFile);
    gcry_cipher_close(cipher);
    gcry_md_close(hash);
    fclose(encFile);

  } else {
    //if there is improper syntax, throw errors
    printf("File was not specified or does not exist\n");
    exit(1);
  }
  return 0;
}
