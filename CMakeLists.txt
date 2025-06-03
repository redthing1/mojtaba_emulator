# CMakeList.txt : CMake project for emulator, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)



# Enable Hot Reload for MSVC compilers if supported.
if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project ("emulator")

add_executable(emulator 
    src/main.cpp
    src/Emulator.cpp
    src/PELoader.cpp
    src/Disassembler.cpp
    src/ImportResolver.cpp
    
 )

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET emulator PROPERTY CXX_STANDARD 20)
endif()

# TODO: Add tests and install targets if needed.
add_subdirectory(deps/LIEF)
target_link_libraries(emulator LIEF::LIEF)

add_subdirectory(deps/unicorn)
target_link_libraries(emulator unicorn)

add_subdirectory(deps/capstone)
target_link_libraries(emulator capstone)
