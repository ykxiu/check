cmake_minimum_required(VERSION 3.10)

# 这里使用project命令，名称与后续引用保持一致
project(main)

# Set C++11
set(CMAKE_CXX_STANDARD 11)
# popen()/pclose() are not C++ standards
set(CMAKE_CXX_EXTENSIONS ON)

set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0")
# 设置源文件列表
set(SRC_LIST main.cpp Frame.h Frame.cpp verify.cpp)

# 添加可执行文件，目标名称为main
add_executable(main ${SRC_LIST})

# 获取main目标的包含目录，注意这里将目标名称改为main
get_target_property(my_app_include_dirs main INCLUDE_DIRECTORIES)
message(STATUS "The include directories of my_app are: ${my_app_include_dirs}")

# 链接Pcap
find_package(PcapPlusPlus REQUIRED)
# We want to have the binary compiled in the same folder as the .cpp to be near the PCAP file
# set_target_properties("${PROJECT_NAME}" PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
# Link with Pcap++ libraries
target_link_libraries("${PROJECT_NAME}" PUBLIC PcapPlusPlus::Pcap++)

find_library(ZMQ_LIBRARY zmq REQUIRED)
target_link_libraries("${PROJECT_NAME}" PUBLIC ${ZMQ_LIBRARY})

# 查找 OpenSSL 库
find_package(OpenSSL REQUIRED)

# 检查是否找到 OpenSSL 库
if(NOT OpenSSL_FOUND)
    message(FATAL_ERROR "OpenSSL not found!")
endif()
# 包含 OpenSSL 头文件目录
target_include_directories(${PROJECT_NAME} PRIVATE ${OpenSSL_INCLUDE_DIR})

# 链接 OpenSSL 库
target_link_libraries(${PROJECT_NAME} PRIVATE OpenSSL::Crypto)

