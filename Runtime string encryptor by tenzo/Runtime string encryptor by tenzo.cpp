#include <iostream>
#include <string>

#include "TenzoRSE.h"

int main()
{
    constexpr auto msg = TENZO_OBFUSCATE("hello world");
    constexpr auto note = TENZO_OBFUSCATE("runtime string stays shuffled and transformed in memory made by tenzo");

    std::cout << msg << '\n';
    std::cout << note << '\n';
    std::cout << TENZO_OBFUSCATE("\npress enter...");
    std::cin.get();
}
