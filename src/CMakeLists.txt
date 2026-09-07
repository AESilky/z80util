# Library: Number and Base Support (obj only)
add_executable(z80util main.c)
#
target_include_directories(z80util BEFORE PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}/src/include
)
#
# Configuration - Release Mode - Debug disabled by default
#
target_compile_definitions(z80util PUBLIC
  DEBUG_MODE=0
  SHELL_ENABLE
  SHELL_NOCASE
)
# Link in the Modules/Libraries for the top-level
target_link_libraries(z80util PUBLIC
)


add_executable(z80util_db main.c)
#
target_include_directories(z80util_db BEFORE PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}/src/include
)
#
# Configuration - Debug Mode enabled by default
#
target_compile_definitions(z80util_db PUBLIC
  DEBUG_MODE=1
  SHELL_ENABLE
  SHELL_NOCASE
)
# Link in the Modules/Libraries for the top-level
target_link_libraries(z80util_db
)


#add_subdirectory(cmd)
