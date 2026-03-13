Feature: Launcher lifecycle

  Background:
    Given a clean working directory
    And the mock gateway is installed as "gateway"
    And the launcher is in prebuilt mode
    And NATS is skipped

  Scenario: Launcher starts and gateway becomes healthy
    When the launcher starts
    Then the gateway PID file exists
    And the launcher is running

  Scenario: Launcher stops cleanly on SIGTERM
    When the launcher starts
    And the gateway becomes healthy
    When the launcher is stopped
    Then the gateway process is no longer alive
    And the gateway PID file is removed

  Scenario: Gateway health check times out and launcher exits with error
    Given the failing mock gateway is installed as "gateway"
    When the launcher starts
    Then the launcher exits with a non-zero code within 12 seconds
