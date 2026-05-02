#include "TenzoRSE.h"
#include <iostream>
#include <string>

bool chkcreds(const std::string& user, const std::string& pass)
{
    if (TENZO_OBFUSCATE("admin").equals(user.c_str()) && TENZO_OBFUSCATE("1").equals(pass.c_str()))
    {
        return true;
    }
    return false;
}

int main()
{
    std::string username, password;
    std::cout << TENZO_OBFUSCATE("username: ");
    std::cin >> username;
    std::cout << TENZO_OBFUSCATE("Password: ");
    std::cin >> password;
    if (chkcreds(username, password))
    {
        std::cout << TENZO_OBFUSCATE("Login done") << std::endl;
    }
    else
    {
        std::cout << TENZO_OBFUSCATE("Login failed");
    }
    std::cin.get();
    std::cin.get();
    return 0;
}
