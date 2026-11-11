cmake_minimum_required(VERSION 3.21)
project(KlamAV VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 6.4 REQUIRED COMPONENTS Widgets Concurrent)

qt_add_executable(klamav
    src/main.cpp
)
target_link_libraries(klamav PRIVATE Qt6::Widgets Qt6::Concurrent)
target_compile_options(klamav PRIVATE -Wall -Wextra -Wpedantic)

install(TARGETS klamav RUNTIME DESTINATION bin)
install(FILES data/org.klamav.KlamAV.desktop DESTINATION share/applications)
