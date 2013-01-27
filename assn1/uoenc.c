#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
  int local = 1;
  char address[16];
  int port;
  char fileName[100];
  int fileSpecified = 0;
  
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
    printf("Password: ");
    char password[32];
    fgets(password, 32, stdin);

    if(local){
    
    } else {
      
    }
  } else {
    printf("File was not specified or does not exist\n");
    exit(1);
  }
  return 0;
}
