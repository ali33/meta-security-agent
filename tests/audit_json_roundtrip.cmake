# Parses the hostile audit JSON emitted by `metasec_audit_tests --emit-json` with CMake's own parser.
execute_process(COMMAND "${EXE}" --emit-json
  RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err)
if(NOT rc EQUAL 0)
  message(FATAL_ERROR "emit-json failed rc=${rc}: ${err}")
endif()

string(JSON host ERROR_VARIABLE e GET "${out}" hostname)
if(e)
  message(FATAL_ERROR "not valid JSON: ${e}\n${out}")
endif()
string(FIND "${host}" "a\"b\\c" p0)
if(NOT p0 EQUAL 0)
  message(FATAL_ERROR "hostname did not round-trip: [${host}]")
endif()

string(JSON n LENGTH "${out}" rules)
if(NOT n EQUAL 7)
  message(FATAL_ERROR "expected 7 rules, got ${n}")
endif()

# FW-003 (index 2): FAIL, with the hostile source string preserved in provenance.
string(JSON res GET "${out}" rules 2 result)
if(NOT res STREQUAL "FAIL")
  message(FATAL_ERROR "FW-003 result: ${res}")
endif()
string(JSON src GET "${out}" rules 2 provenance sources 0)
if(NOT src STREQUAL "src\\\"x")
  message(FATAL_ERROR "source did not round-trip: [${src}]")
endif()

# AV-002 (index 4): PASS; the active engine name with quotes, newline and backslash round-trips.
string(JSON res GET "${out}" rules 4 result)
if(NOT res STREQUAL "PASS")
  message(FATAL_ERROR "AV-002 result: ${res}")
endif()
string(JSON eng GET "${out}" rules 4 evidence active_engine)
if(NOT eng STREQUAL "Evil \"AV\"\n\\")
  message(FATAL_ERROR "product name did not round-trip: [${eng}]")
endif()
string(JSON overall GET "${out}" overall)
if(NOT overall STREQUAL "FINDINGS")
  message(FATAL_ERROR "overall: ${overall}")
endif()
