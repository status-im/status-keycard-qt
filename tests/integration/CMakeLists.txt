find_package(Qt6 REQUIRED COMPONENTS Test Network)

set(INTEGRATION_FIXTURE_SOURCES
    fixtures/simulator_process.cpp
    fixtures/simulator_client.cpp
    fixtures/rpc_client.cpp
    fixtures/integration_test_base.cpp
)

add_library(integration_fixtures STATIC ${INTEGRATION_FIXTURE_SOURCES})
target_link_libraries(integration_fixtures
    PUBLIC
        status-keycard-qt
        Qt6::Test
        Qt6::Core
        Qt6::Network
)
target_include_directories(integration_fixtures
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/fixtures
        ${CMAKE_SOURCE_DIR}/src
)
target_compile_definitions(integration_fixtures
    PUBLIC
        KEYCARD_SIMULATOR_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../../test/keycard-simulator"
)
set_target_properties(integration_fixtures PROPERTIES AUTOMOC ON)

# Registers <name>_v3 (applet 3.2, password pairing) and/or <name>_v4 (applet 4.0, SecureChannelV2).
# Default: both. Pass V3_ONLY or V4_ONLY for flows that exist on one generation only.
function(add_integration_test TEST_NAME)
    cmake_parse_arguments(ARG "V3_ONLY;V4_ONLY" "" "" ${ARGN})
    add_executable(${TEST_NAME} ${TEST_NAME}.cpp)
    target_link_libraries(${TEST_NAME} PRIVATE integration_fixtures)

    set(applets "")
    if(NOT ARG_V4_ONLY)
        list(APPEND applets "v3:3.2")
    endif()
    if(NOT ARG_V3_ONLY)
        list(APPEND applets "v4:4.0")
    endif()
    foreach(entry IN LISTS applets)
        string(REPLACE ":" ";" parts "${entry}")
        list(GET parts 0 suffix)
        list(GET parts 1 applet)
        add_test(NAME ${TEST_NAME}_${suffix} COMMAND ${TEST_NAME} -maxwarnings 0)
        set_tests_properties(${TEST_NAME}_${suffix} PROPERTIES
            LABELS "integration;integration-${suffix}"
            ENVIRONMENT "KEYCARD_SIM_APPLET=${applet}"
            RESOURCE_LOCK "keycard-simulator"
            TIMEOUT 300
        )
    endforeach()
endfunction()

add_integration_test(test_integration_smoke)
add_integration_test(test_load_recover)
add_integration_test(test_pin_block_unblock)
add_integration_test(test_factory_reset)
add_integration_test(test_cancel_remove)
add_integration_test(test_pairing V3_ONLY)
add_integration_test(test_change_pin_puk)
add_integration_test(test_presence)
add_integration_test(test_sign_export)
add_integration_test(test_simulator_power)
add_integration_test(test_secure_channel_v2 V4_ONLY)
