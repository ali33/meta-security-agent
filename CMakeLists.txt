cmake_minimum_required(VERSION 3.20)
project(meta_security_agent VERSION 0.1.0 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT WIN32)
  message(FATAL_ERROR "MVP-0 currently targets Windows only")
endif()

# Pure, OS-independent security core (JSON, types, rendering, CLI parsing).
add_library(metasec_core STATIC
  src/core/json.cpp
  src/core/types.cpp
  src/core/interpret.cpp
  src/core/audit.cpp
  src/core/render.cpp
  src/core/cli.cpp)
target_include_directories(metasec_core PUBLIC src)

# Windows providers (firewall, Security Center, Defender via WMI).
add_library(metasec_win STATIC
  src/win/host_win.cpp
  src/win/firewall_win.cpp
  src/win/wsc_win.cpp
  src/win/defender_win.cpp
  src/win/av_products_win.cpp
  src/win/collect_win.cpp)
target_link_libraries(metasec_win PUBLIC metasec_core ole32 oleaut32 wbemuuid)

add_executable(meta-sec src/main.cpp)
target_link_libraries(meta-sec PRIVATE metasec_win)
target_compile_definitions(meta-sec PRIVATE META_SEC_VERSION="${PROJECT_VERSION}")

foreach(t metasec_core metasec_win meta-sec)
  target_compile_definitions(${t} PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
  if(MSVC)
    target_compile_options(${t} PRIVATE /W4 /WX /EHsc /utf-8 /permissive- /sdl /guard:cf)
  endif()
endforeach()
if(MSVC)
  # Hardening: control-flow guard, CET shadow stack, and no DLL search-path planting.
  target_link_options(meta-sec PRIVATE /guard:cf /CETCOMPAT /DEPENDENTLOADFLAG:0x800)
endif()

include(CTest)
if(BUILD_TESTING)
  add_executable(metasec_tests tests/test_core.cpp)
  target_link_libraries(metasec_tests PRIVATE metasec_core)
  target_compile_definitions(metasec_tests PRIVATE NOMINMAX)
  if(MSVC)
    target_compile_options(metasec_tests PRIVATE /W4 /WX /EHsc /utf-8 /permissive-)
  endif()
  add_test(NAME core_unit COMMAND metasec_tests)

  add_test(NAME json_roundtrip
    COMMAND ${CMAKE_COMMAND} -DEXE=$<TARGET_FILE:metasec_tests>
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/json_roundtrip.cmake)

  # End-to-end tests drive the real executable; JSON validity is checked by CMake's own parser.
  foreach(mode help version status_text status_json bad_command bad_flag no_args)
    add_test(NAME cli_${mode}
      COMMAND ${CMAKE_COMMAND} -DEXE=$<TARGET_FILE:meta-sec> -DMODE=${mode}
              -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/cli_check.cmake)
  endforeach()
endif()
