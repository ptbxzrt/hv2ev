cmake_minimum_required(VERSION 3.10)

add_executable(test test_main.cpp test1.cpp)

set(hv_DIR "/home/ptbxzrt/third_party/libhv")

target_include_directories(test PUBLIC "${hv_DIR}/include")

target_link_directories(test PUBLIC "${hv_DIR}/lib")

target_link_libraries(test PUBLIC hv)