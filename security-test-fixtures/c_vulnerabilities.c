#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *password = "demo-cno a-password-123456789";

void vulnerable(const char *input) {
  char buffer[16];
  strcpy(buffer, input);
  printf(input);
  system(input);
}
