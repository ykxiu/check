cmake_minimum_required(VERSION 3.10)

# 这里使用project命令，名称与后续引用保持一致
project(main)

# 设置源文件列表
set(SRC_LIST main.cpp)

# 添加可执行文件，目标名称为main
add_executable(main ${SRC_LIST})

# 获取main目标的包含目录，注意这里将目标名称改为main
get_target_property(my_app_include_dirs main INCLUDE_DIRECTORIES)
message(STATUS "The include directories of my_app are: ${my_app_include_dirs}")

find_library(ZMQ_LIBRARY zmq REQUIRED)
target_link_libraries("${PROJECT_NAME}" PUBLIC ${ZMQ_LIBRARY})

find_package(PcapPlusPlus REQUIRED)
# We want to have the binary compiled in the same folder as the .cpp to be near the PCAP file
# set_target_properties("${PROJECT_NAME}" PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
# Link with Pcap++ libraries
target_link_libraries("${PROJECT_NAME}" PUBLIC PcapPlusPlus::Pcap++)

