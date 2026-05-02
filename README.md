# TenzoRSE

runtime string encryption. header only c++17+. hides from IDA, x64dbg
strings cmd. decodes char by char so full plaintext never sits in memory.
compile time shuffle plus xor plus bit rotate. seed changes every build.
no heap, no deps.

## showcase

tested against real tools so you dont have to wonder if it actually works

https://files.catbox.moe/6qndlx.mp4

## usage

```cpp
#include "TenzoRSE.h"

int main()
{
    auto token = TENZO_OBFUSCATE("very_peak_token");

    token.each([](char c) {
        send_to_api(c);
    });

    if (token.equals(user_input)) {
        grant_access();
    }

    char buf[128];
    token.into(buf, sizeof(buf));
    tenzo::detail::wipe(buf, sizeof(buf));
}
