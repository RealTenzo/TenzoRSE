# TenzoRSE

runtime string encryption. header only c++17+. hides from IDA, x64dbg
strings cmd. decodes char by char so full plaintext never sits in memory.
compile time shuffle plus xor plus bit rotate. seed changes every build.
no heap, no deps.

## showcase

tested against real tools so you dont have to wonder if it actually works

[watch the demo](https://files.catbox.moe/6qndlx.mp4)


## usage (auto)

write plain strings. the pre-build step rewrites every literal to
`TENZO_AUTO(...)` before compile, so the exe never holds plaintext.

```cpp
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
```

build the project, the pre-build event runs:

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$(MSBuildProjectDirectory)\..\tools\autoenc.ps1" -SrcDir "$(MSBuildProjectDirectory)" -OutDir "$(IntDir)autoenc"
```

it copies the sources to `$(IntDir)autoenc` with each `"literal"`
turned into `TENZO_AUTO("literal")`, and the build compiles that copy.
`strings` on the exe shows none of the literals above.

manual mode still works if you want it: `TENZO_OBFUSCATE("txt")`
returns the object (`equals`, `each`, `into`, `open`, `==`),
`TENZO_AUTO("txt")` returns `const char*` (safe for `printf` varargs).
