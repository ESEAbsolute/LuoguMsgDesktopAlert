使用前请在 cookie.txt 里填入洛谷的 __uid __client_id。需要登录。

查看 cookie：F12 - 应用 - 存储 - Cookie

双击 main.exe 打开

编译 .cpp 程序需要配置 cpp-httplib, openssl, websocketpp, boost 和 nlohmann/json.hpp。若未配置好所需的库和头文件，程序会编译失败。打包 .js 程序需要安装 node.js 18。其他版本大概也可以，我不确定。

----------

依赖：
- [cpp-httplib](https://github.com/yhirose/cpp-httplib): `benchmark/cpp-httplib-base/httplib.h`
- [json](https://github.com/nlohmann/json): `include/nlohmann`
- [websocketpp](https://github.com/zaphoyd/websocketpp): `websocketpp`
  - [Boost](https://github.com/boostorg): [1.86.0](https://archives.boost.io/release/1.86.0/source/boost_1_86_0.zip)
  - [openssl](https://github.com/openssl/openssl): [Win64 OpenSSL v3.3.2](https://slproweb.com/products/Win32OpenSSL.html)
- [fmt](https://github.com/fmtlib/fmt): `include/fmt`
- [imgui](https://github.com/ocornut/imgui): GLFW x OpenGL3
  - [GLFW](https://github.com/glfw/glfw): `include/GLFW`

