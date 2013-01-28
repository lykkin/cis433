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

int local = 1;
  char address[16];
  int port;
  char fileName[100];
  int fileSpecified = 0;
  char salt[16];
  char password[32];
  char key[32];
  
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
          char portString[16];
          memcpy (portString, argv[i] + j + 1, strlen(argv[i]) - j - 1);
          portString[strlen(argv[i]) - j - 1] = '\0';
          port = atoi(portString);
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
      printf("Output file already exists, exitting.\n");
      fclose(srcFile);
      fclose(encFile);
      exit(1);
    }
    //Get a password from the user
    printf("Password: ");
    for(i = 0; i < 32; i++){
      password[i] = '\0';
    }
    fgets(password, 32, stdin);
    //generate a salt and key
    gcry_randomize(salt, 16, GCRY_STRONG_RANDOM);
    salt[15] = '\0';
    gpg_error_t err = gcry_kdf_derive(password, strlen(password), GCRY_KDF_PBKDF2, GCRY_MD_SHA256, salt, strlen(salt), 100, 32, key);
    key[31] = '\0';
    
    if(local){
    
    } else {
      
    }
  } else {
    printf("File was not specified or does not exist\n");
    exit(1);
  }
  return 0;
}
