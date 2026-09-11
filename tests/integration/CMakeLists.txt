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

function(add_integration_test TEST_NAME)
    add_executable(${TEST_NAME} ${TEST_NAME}.cpp)
    target_link_libraries(${TEST_NAME} PRIVATE integration_fixtures)
    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME} -maxwarnings 0)
    set_tests_properties(${TEST_NAME} PROPERTIES
        LABELS "integration"
        RESOURCE_LOCK "keycard-simulator"
    )
endfunction()

add_integration_test(test_integration_smoke)
add_integration_test(test_load_recover)
add_integration_test(test_pin_block_unblock)
add_integration_test(test_factory_reset)
add_integration_test(test_cancel_remove)
add_integration_test(test_pairing)
add_integration_test(test_change_pin_puk)
add_integration_test(test_presence)
add_integration_test(test_sign_export)
