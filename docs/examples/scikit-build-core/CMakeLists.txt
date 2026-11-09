cmake_minimum_required(VERSION 3.15...3.31)
project(${SKBUILD_PROJECT_NAME} LANGUAGES C)

find_package(Python COMPONENTS Interpreter Development.Module REQUIRED)
python_add_library(_greet MODULE src/greet/_greet.c WITH_SOABI)
install(TARGETS _greet DESTINATION greet)
