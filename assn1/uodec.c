#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gcrypt.h>

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

  int port;
  char fileName[100];
  char salt[17];
  char password[33];
  char key[33];
  int fileSpecified = 0; 
  if(argc < 2 || argc > 3){
    printf("Incorrect syntax, should be: ./uodec <port>  [-l <file name>]");
    exit(1);
  }
  int i;
  for(i = 1; i < argc; i++){
    if(strncmp(argv[i], "-l", 2) == 0){
      fileSpecified = 1;
      strcpy(fileName, argv[++i]);
    } else {
      port = atoi(argv[i]);
    }

  }
  
  FILE *srcFile = fopen(fileName, "r");
  if(fileSpecified && srcFile){
    char decFileName[100];
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
    //generate a salt and key
    gcry_randomize(salt, 16, GCRY_STRONG_RANDOM);
    salt[16] = '\0';
    gpg_error_t err = gcry_kdf_derive(password, strlen(password), GCRY_KDF_PBKDF2, GCRY_MD_SHA256, salt, strlen(salt), 100, 32, key);
    key[32] = '\0';
    //fputs(salt, decFile);
    gcry_cipher_hd_t cipher;
    err = gcry_cipher_open(&cipher, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0);
    err = gcry_cipher_setkey(cipher, key, strlen(key));
    err = gcry_cipher_setiv(cipher, salt, strlen(salt));
    char curBlock[1025];
    char outBlock[1025];
    while(!feof(srcFile)){
      fread(curBlock, 1, 1024, srcFile);
      curBlock[1024] = '\0';
      gcry_cipher_decrypt(cipher, curBlock, 1024, curBlock, 1024);
      fread(curBlock, 1, 1024, srcFile);
      fwrite(curBlock, 1, 1024, decFile);
    }
      gcry_cipher_decrypt(cipher, curBlock, 1024, curBlock, 1024);

    if(local){
    
    } else {
      
    }
  } else {
    printf("File was not specified or does not exist\n");
    exit(1);
  }
  return 0;
}
