cmake_minimum_required(VERSION 3.21)
project(KlamAV VERSION 1.0.4 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 6.4 REQUIRED COMPONENTS Widgets Concurrent)

qt_add_executable(klamav
    src/main.cpp
    src/scanengine.cpp
    src/fileoperations.cpp
    src/systemdscheduler.cpp
)
target_link_libraries(klamav PRIVATE Qt6::Widgets Qt6::Concurrent)
target_compile_definitions(klamav PRIVATE KLAMAV_VERSION="${PROJECT_VERSION}")
target_compile_options(klamav PRIVATE -Wall -Wextra -Wpedantic)

install(TARGETS klamav RUNTIME DESTINATION bin)
install(FILES data/org.klamav.KlamAV.desktop DESTINATION share/applications)

include(CTest)
if(BUILD_TESTING)
    find_package(Qt6 6.4 REQUIRED COMPONENTS Test)
    qt_add_executable(klamav_tests
        tests/core_tests.cpp
        src/scanengine.cpp
        src/fileoperations.cpp
        src/systemdscheduler.cpp
    )
    target_include_directories(klamav_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(klamav_tests PRIVATE Qt6::Core Qt6::Concurrent Qt6::Test)
    target_compile_options(klamav_tests PRIVATE -Wall -Wextra -Wpedantic)
    add_test(NAME klamav_core_tests COMMAND klamav_tests)
endif()
