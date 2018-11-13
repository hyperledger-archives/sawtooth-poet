if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CARGO_CMD cargo build)
    set(TARGET_DIR "debug")
else ()
    set(CARGO_CMD cargo build --release)
    set(TARGET_DIR "release")
endif ()

#set scope to both current and parent. This variable is used by other modules
set(RUST_SGXFFI_SO_NAME "libsgxffi.so")
set(RUST_SGXFFI_SO_NAME ${RUST_SGXFFI_SO_NAME} PARENT_SCOPE)

set(RUST_SGXFFI_SO_PATH "${CMAKE_CURRENT_BINARY_DIR}/${TARGET_DIR}/${RUST_SGXFFI_SO_NAME}")

add_custom_target(${RUST_SGXFFI} ALL
    COMMENT "Compiling rust sgx ffi library module"
    COMMAND CARGO_TARGET_DIR=${CMAKE_CURRENT_BINARY_DIR} ${CARGO_CMD} 
    COMMAND cp ${RUST_SGXFFI_SO_PATH} ${EXECUTABLE_OUTPUT_PATH}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

#Build Rust SGX bridge C++ code before building rust FFI
add_dependencies(${RUST_SGXFFI} ${RUST_SGX_BRIDGE})

set_target_properties(${RUST_SGXFFI} PROPERTIES LOCATION ${EXECUTABLE_OUTPUT_PATH})

add_test(NAME rust_sgxffi_test 
    COMMAND cargo test --lib
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})