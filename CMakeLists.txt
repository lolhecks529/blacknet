cmake_minimum_required(VERSION 3.10)
project(blacknet LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(CURL REQUIRED libcurl)
pkg_check_modules(SSL REQUIRED libssl libcrypto)

option(ENABLE_GUI "Build with Qt5 GUI support" OFF)

if(ENABLE_GUI)
    find_package(Qt5 COMPONENTS Widgets Network QUIET)
    if(Qt5_FOUND)
        add_definitions(-DENABLE_GUI)
    endif()
endif()

set(SOURCES
    src/main.cpp
    src/AttackEngine.cpp
    src/ProtocolHandler.cpp
    src/GeoLocator.cpp
    src/ProxyManager.cpp
    src/PacketBuilder.cpp
    src/BotManager.cpp
    src/Utilities.cpp
)

if(ENABLE_GUI AND Qt5_FOUND)
    list(APPEND SOURCES src/GUI.cpp)
endif()

add_executable(blacknet ${SOURCES})
target_include_directories(blacknet PRIVATE include)

target_link_libraries(blacknet PRIVATE
    ${CURL_LIBRARIES}
    ${SSL_LIBRARIES}
    pthread
)

if(ENABLE_GUI AND Qt5_FOUND)
    target_link_libraries(blacknet PRIVATE Qt5::Widgets Qt5::Network)
endif()

# Bot target (standalone)
add_executable(bot EXCLUDE_FROM_ALL bot.cpp)
target_link_libraries(bot PRIVATE pthread)
