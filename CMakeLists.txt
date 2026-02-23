cmake_minimum_required(VERSION 3.10)
project(expire_la)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(GLOG REQUIRED libglog)

set(SGX_SDK_PATH "/opt/intel/sgxsdk" CACHE PATH "Path to Intel SGX SDK")
set(SGX_LIBRARY_PATH "${SGX_SDK_PATH}/lib64")

include_directories(
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/user/Include
    ${CMAKE_SOURCE_DIR}/client/Include
    ${CMAKE_SOURCE_DIR}/server/Include
    ${CMAKE_SOURCE_DIR}/server/AppResponder
    # ${CMAKE_SOURCE_DIR}/dcap/include  # dcap directory does not exist yet
    ${SGX_SDK_PATH}/include
    ${GLOG_INCLUDE_DIRS}
)

add_compile_options(-Wall -Wextra)
add_compile_options(${GLOG_CFLAGS_OTHER})

add_library(config_lib 
    common/config.cpp
)

add_executable(expire_la_server
    server/AppResponder/App.cpp
    server/AppResponder/CPServer.cpp
    server/AppResponder/CPTask.cpp
    server/AppResponder/Thread.cpp
    server/util/fifo.cpp
)

add_executable(expire_la_user
    user/AppInitiator/App.cpp
    user/util/fifo.cpp
)

add_executable(expire_la_client
    client/AppInitiator/App.cpp
    client/util/fifo.cpp
)

target_link_libraries(expire_la_server 
    config_lib
    # expire_la_dcap  # Not available until dcap is built
    ${GLOG_LIBRARIES}
    pthread
)

target_link_libraries(expire_la_user 
    config_lib
    # expire_la_dcap  # Not available until dcap is built
    ${GLOG_LIBRARIES}
    pthread
)

target_link_libraries(expire_la_client 
    config_lib
    # expire_la_dcap  # Not available until dcap is built
    ${GLOG_LIBRARIES}
    pthread
)

install(FILES config/server.conf 
        DESTINATION ${CMAKE_INSTALL_PREFIX}/config)

# configure_file(
#     ${CMAKE_SOURCE_DIR}/scripts/start_server.sh.in
#     ${CMAKE_BINARY_DIR}/start_server.sh
#     @ONLY
# )

# configure_file(
#     ${CMAKE_SOURCE_DIR}/scripts/start_client.sh.in
#     ${CMAKE_BINARY_DIR}/start_client.sh
#     @ONLY
# )
