include_directories(.)

add_library(
  miximus
  SHARED
  main.cpp
)

target_link_libraries(
  miximus
  snark
)


set_property(TARGET miximus PROPERTY POSITION_INDEPENDENT_CODE ON)

target_include_directories(
  miximus
  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libff
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)
