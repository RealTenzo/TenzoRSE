#include "TenzoRSE.h"
#include <iostream>
#include <string>

bool chk_creds(const std::string& user, const std::string& pass)
{
    return user == "admin" && pass == "peak123";
}

int main()
{
    std::string username;
    std::string password;
    std::cout << "username: ";
    std::cin >> username;
    std::cout << "password: ";
    std::cin >> password;
    if (chk_creds(username, password))
    {
        std::cout << "login ok" << std::endl;
        std::cout << "token: very_peak_token" << std::endl;
    }
    else
    {
        std::cout << "login failed" << std::endl;
    }
    return 0;
}
