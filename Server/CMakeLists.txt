cmake_minimum_required(VERSION 3.10)

# set the project name
project(Openssl-with-bio-Server VERSION 1.0)

set(OPENSSL_USE_STATIC_LIBS TRUE)
set(SOURCE_FILES Main.cpp OpenSSL_BIO_Server.cpp)
find_package(OpenSSL REQUIRED)


# add the executable
add_executable(${PROJECT_NAME} ${SOURCE_FILES})

target_include_directories(${PROJECT_NAME} PUBLIC
                           "${PROJECT_BINARY_DIR}"
                           "${PROJECT_SOURCE_DIR}"
                           )

target_link_libraries(${PROJECT_NAME} OpenSSL::Crypto ssl crypto)
