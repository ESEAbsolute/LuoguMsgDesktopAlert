cmake_minimum_required(VERSION 3.29)
project(Project)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
#set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")

#set(Boost_COMPILER "-mgw13")
#set(Boost_USE_STATIC_LIBS ON)

include_directories(CppSourceRefactored/include)
include_directories(Dependencies)
include_directories(C:/boost-msvc)
include_directories("C:/Program Files/OpenSSL/include")

add_executable(Project
        CppSourceRefactored/main.cpp
        CppSourceRefactored/include/client/HTTPClient.hpp
#        CppSourceRefactored/include/client/WebSocketClient.hpp
#        CppSourceRefactored/include/event/handler/Event.hpp
#        CppSourceRefactored/include/event/handler/EventListener.hpp
#        CppSourceRefactored/include/event/handler/EventManager.hpp
#        CppSourceRefactored/include/event/ListenersImpl.hpp
#        CppSourceRefactored/include/event/IBroadcastListener.hpp
#        CppSourceRefactored/include/event/IUpdateListener.hpp
#        CppSourceRefactored/include/ESEAbs0Misc.hpp
#        CppSourceRefactored/include/FileUtils.hpp
#        CppSourceRefactored/include/MsgManager.hpp
#        CppSourceRefactored/include/LocalLogger.hpp
)
target_compile_options(Project PRIVATE
        -Wall
#        -O2
)

target_link_libraries(Project ws2_32 crypt32 cryptui)

find_package(OpenSSL)
include_directories(${OPENSSL_INCLUDE_DIR})
target_link_libraries(Project ${OPENSSL_LIBRARIES})

