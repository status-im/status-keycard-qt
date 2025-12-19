# Simple usage example
add_executable(simple_usage simple_usage.cpp)

target_link_libraries(simple_usage
    PRIVATE status-keycard-qt
)

# Hardware test (Phase 5)
add_executable(test_hardware test_hardware.cpp)

target_link_libraries(test_hardware
    PRIVATE status-keycard-qt
)

# Install
install(TARGETS simple_usage test_hardware
    RUNTIME DESTINATION bin/examples
)

