cmake_minimum_required(VERSION 3.20)
project(meta_security_agent VERSION 0.1.0 LANGUAGES C CXX)
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
  src/core/watch.cpp
  src/core/scan.cpp
  src/core/render.cpp
  src/core/cli.cpp)
target_include_directories(metasec_core PUBLIC src)

# Vendored SQLite amalgamation (public domain, unmodified). Third-party code: warnings are not
# promoted to errors and /W4 /WX /sdl are deliberately not applied to this target only.
add_library(sqlite3_vendor STATIC third_party/sqlite/sqlite3.c)
target_include_directories(sqlite3_vendor PUBLIC third_party/sqlite)
target_compile_definitions(sqlite3_vendor PRIVATE
  SQLITE_THREADSAFE=1 SQLITE_OMIT_LOAD_EXTENSION SQLITE_DEFAULT_MEMSTATUS=0 SQLITE_OMIT_DEPRECATED
  SQLITE_DQS=0 SQLITE_OMIT_SHARED_CACHE SQLITE_DEFAULT_FOREIGN_KEYS=1 SQLITE_USE_URI=0)
if(MSVC)
  target_compile_options(sqlite3_vendor PRIVATE /W0 /guard:cf)
endif()

# Local event store (SQLite). Still free of Windows headers.
add_library(metasec_store STATIC src/core/store.cpp src/core/observer.cpp)
target_link_libraries(metasec_store PUBLIC metasec_core PRIVATE sqlite3_vendor)

# Windows providers (firewall, Security Center, Defender via WMI).
add_library(metasec_win STATIC
  src/win/host_win.cpp
  src/win/firewall_win.cpp
  src/win/wsc_win.cpp
  src/win/defender_win.cpp
  src/win/av_products_win.cpp
  src/win/scan_win.cpp
  src/win/collect_win.cpp)
target_link_libraries(metasec_win PUBLIC metasec_core ole32 oleaut32 wbemuuid secur32)

add_executable(meta-sec src/main.cpp)
target_link_libraries(meta-sec PRIVATE metasec_win)
target_compile_definitions(meta-sec PRIVATE META_SEC_VERSION="${PROJECT_VERSION}")

foreach(t metasec_core metasec_store metasec_win meta-sec)
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

  add_executable(metasec_audit_tests tests/test_audit.cpp)
  target_link_libraries(metasec_audit_tests PRIVATE metasec_core)
  target_compile_definitions(metasec_audit_tests PRIVATE NOMINMAX)
  if(MSVC)
    target_compile_options(metasec_audit_tests PRIVATE /W4 /WX /EHsc /utf-8 /permissive-)
  endif()
  add_test(NAME audit_unit COMMAND metasec_audit_tests)
  add_test(NAME audit_json_roundtrip
    COMMAND ${CMAKE_COMMAND} -DEXE=$<TARGET_FILE:metasec_audit_tests>
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/audit_json_roundtrip.cmake)

  add_executable(metasec_watch_tests tests/test_watch.cpp)
  target_link_libraries(metasec_watch_tests PRIVATE metasec_core)
  target_compile_definitions(metasec_watch_tests PRIVATE NOMINMAX)
  if(MSVC)
    target_compile_options(metasec_watch_tests PRIVATE /W4 /WX /EHsc /utf-8 /permissive-)
  endif()
  add_test(NAME watch_unit COMMAND metasec_watch_tests)
  add_test(NAME watch_ndjson_roundtrip
    COMMAND ${CMAKE_COMMAND} -DEXE=$<TARGET_FILE:metasec_watch_tests>
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/watch_ndjson_roundtrip.cmake)

  add_executable(metasec_scan_tests tests/test_scan.cpp)
  target_link_libraries(metasec_scan_tests PRIVATE metasec_core)
  target_compile_definitions(metasec_scan_tests PRIVATE NOMINMAX)
  if(MSVC)
    target_compile_options(metasec_scan_tests PRIVATE /W4 /WX /EHsc /utf-8 /permissive-)
  endif()
  add_test(NAME scan_unit COMMAND metasec_scan_tests)

  add_executable(metasec_store_tests tests/test_store.cpp)
  target_link_libraries(metasec_store_tests PRIVATE metasec_store sqlite3_vendor)
  target_compile_definitions(metasec_store_tests PRIVATE NOMINMAX)
  target_include_directories(metasec_store_tests PRIVATE tests)
  if(MSVC)
    target_compile_options(metasec_store_tests PRIVATE /W4 /WX /EHsc /utf-8 /permissive-)
  endif()
  add_test(NAME store_unit COMMAND metasec_store_tests)

  add_executable(metasec_observer_tests tests/test_observer.cpp)
  target_link_libraries(metasec_observer_tests PRIVATE metasec_store)
  target_compile_definitions(metasec_observer_tests PRIVATE NOMINMAX)
  target_include_directories(metasec_observer_tests PRIVATE tests)
  if(MSVC)
    target_compile_options(metasec_observer_tests PRIVATE /W4 /WX /EHsc /utf-8 /permissive-)
  endif()
  add_test(NAME observer_unit COMMAND metasec_observer_tests)

  add_test(NAME json_roundtrip
    COMMAND ${CMAKE_COMMAND} -DEXE=$<TARGET_FILE:metasec_tests>
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/json_roundtrip.cmake)

  # End-to-end tests drive the real executable; JSON validity is checked by CMake's own parser.
  foreach(mode help version status_text status_json audit_text audit_json audit_bad_flag watch_text watch_json watch_bad_args scan_dry_run scan_json scan_no_approval scan_bad_args bad_command bad_flag no_args)
    add_test(NAME cli_${mode}
      COMMAND ${CMAKE_COMMAND} -DEXE=$<TARGET_FILE:meta-sec> -DMODE=${mode}
              -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/cli_check.cmake)
  endforeach()
endif()
