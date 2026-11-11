cmake_minimum_required(VERSION 3.21)
project(KlamAV VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 6.4 REQUIRED COMPONENTS Widgets Concurrent)

qt_add_executable(klamav
    src/main.cpp
    src/main_window.h
    src/main_window_ui.cpp
    src/main_window_scan.cpp
    src/main_window_storage.cpp
    resources/icons.qrc
)
target_link_libraries(klamav PRIVATE Qt6::Widgets Qt6::Concurrent)
target_compile_definitions(klamav PRIVATE KLAMAV_VERSION="${PROJECT_VERSION}")
target_compile_options(klamav PRIVATE -Wall -Wextra -Wpedantic)

install(TARGETS klamav RUNTIME DESTINATION bin)
install(FILES data/org.klamav.KlamAV.desktop DESTINATION share/applications)
install(FILES data/klamav-scan.desktop DESTINATION share/kio/servicemenus)
install(FILES data/icons/org.klamav.KlamAV.svg
    DESTINATION share/icons/hicolor/scalable/apps)
