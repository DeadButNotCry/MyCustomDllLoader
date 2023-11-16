cmake_minimum_required(VERSION 3.26)
project(language_c C)

set(CMAKE_C_STANDARD 11)


add_executable(language_c main.c
        pe_loader.c
        pe_loader.h
)