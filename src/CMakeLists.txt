include_directories(.)


add_library(
  roll_up_wrapper
  SHARED
  roll_up_wrapper.cpp
)

target_link_libraries(
  roll_up_wrapper
  snark
  baby_jubjub_ecc  
)

target_include_directories(roll_up_wrapper PUBLIC ../depends/baby_jubjub_ecc/src)

set_property(TARGET roll_up_wrapper PROPERTY POSITION_INDEPENDENT_CODE ON)

target_include_directories(
  roll_up_wrapper
  PUBLIC
  ${DEPENDS_DIR}/baby_jubjub_ecc
  ${DEPENDS_DIR}/baby_jubjub_ecc/baby_jubjub_ecc
  ${DEPENDS_DIR}/baby_jubjub_ecc/depends/libsnark
  ${DEPENDS_DIR}/baby_jubjub_ecc/depends/libsnark/depends/libff
  ${DEPENDS_DIR}/baby_jubjub_ecc/depends/libsnark/depends/libfqfft
)
