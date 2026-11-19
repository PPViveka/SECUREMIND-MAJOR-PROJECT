#include <cstdlib>
#include <cstring>

const char *api_key = "demo-cpp-key-123456789";

void vulnerable(const char *input) {
  char buffer[16];
  strcpy(buffer, input);
  std::string command = std::string("echo ") + input;
  std::system(command.c_str());
}
