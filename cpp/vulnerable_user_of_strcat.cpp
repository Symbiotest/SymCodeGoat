#include <iostream>
#include <cstring>

int main() {
    char dest[10] = "Hello";
    char src[] = "World";

    strcat(dest, src); // Unsafe: potential buffer overflow

    std::cout << dest << std::endl;
    return 0;
}