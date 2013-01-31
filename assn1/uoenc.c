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

  int local = 1;
  char address[17];
  char port[8];
  char fileName[100];
  int fileSpecified = 0;
  char salt[17];
  char password[33];
  char key[33];
  int s; 
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
  
  FILE *srcFile = fopen(fileName, "r");
  if(fileSpecified && srcFile){
    char encFileName[100];
    strcpy(encFileName, fileName);
    strcat(encFileName, ".uo");
    FILE * encFile = fopen(encFileName, "a+");
    if(fgetc(encFile) != EOF){
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
    gpg_error_t err = gcry_kdf_derive(password, strlen(password), GCRY_KDF_PBKDF2, GCRY_MD_SHA256, salt, strlen(salt), 100, 32, key);
    key[32] = '\0';
    fputs(salt, encFile);
    gcry_cipher_hd_t cipher;
    gcry_md_hd_t hash;
      printf("salt:%s\nkey:%s\n", salt, key);
    err = gcry_cipher_open(&cipher, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0);
    err = gcry_cipher_setkey(cipher, key, 32);
    err = gcry_cipher_setiv(cipher, salt, 16);
    err = gcry_md_open(&hash, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);
    err = gcry_md_setkey(hash, key, 32);
    char curBlock[1056];
    int readlen;
    int padding;
    int totalSize = 0;
    while(!feof(srcFile)){
      for(i = 0; i < 1056; i++){
          curBlock[i] = 0;
      }
      readlen = fread(curBlock, 1, 1024, srcFile);
      padding = readlen % 16 ? 16 - (readlen % 16) : 0;
      readlen += padding;
      gcry_md_write(hash, curBlock, readlen);
      memcpy(curBlock + readlen, gcry_md_read(hash, GCRY_MD_SHA256), 32);
      readlen += 32;
      printf("read %d bytes, wrote %d bytes,\n", readlen - 32, readlen);
      totalSize += readlen;
      gcry_cipher_encrypt(cipher, curBlock, readlen, NULL, 0);
      readlen = fwrite(curBlock, 1, readlen, encFile);
    }
    printf("Successfully encrypted %s to %s (%d bytes written).\n", fileName, encFileName, totalSize);
    if(!local){
      hints.ai_family = AF_INET;
      getaddrinfo(address, port, &hints, &servinfo);
      s = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
      bind(s, servinfo->ai_addr, servinfo->ai_addrlen);
    } 

    fclose(srcFile);
    fclose(encFile);
    gcry_cipher_close(cipher);
    gcry_md_close(hash);


  } else {
    printf("File was not specified or does not exist\n");
    exit(1);
  }
  return 0;
}
