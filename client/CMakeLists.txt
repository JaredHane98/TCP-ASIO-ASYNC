cmake_minimum_required(VERSION 3.5 FATAL_ERROR)
project(TCP_CLIENT VERSION 1.0.0 LANGUAGES CXX)




add_compile_options(-fPIC)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread -fPIC")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread -fPIC")
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(OPENCV_MIN_VERSION "4.4") 

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

if(CMAKE_VERSION VERSION_LESS "3.7.0")
    set(CMAKE_INCLUDE_CURRENT_DIR ON)
endif()


find_package(Boost ${BOOST_MIN_VERSION} REQUIRED COMPONENTS system thread regex serialization log filesystem)
    if(NOT Boost_FOUND)
        message(FETAL_ERROR "Boost > 1.65.1 not found")
    else()
        message("BOOST VERSION FOUND: ${Boost_VERSION}")
    endif()

find_package(OpenSSL REQUIRED)


add_executable(${PROJECT_NAME}
                 main.cpp
               ${PROJECT_SOURCE_DIR}/../common/src/TCPClientManager.cpp)



include_directories(${PROJECT_SOURCE_DIR}
                    ${Boost_INCLUDE_DIRS}
                    ${PROJECT_SOURCE_DIR}/../common/include)



target_link_libraries(${PROJECT_NAME} 
                      ${Boost_LIBRARIES}
                      OpenSSL::SSL)

