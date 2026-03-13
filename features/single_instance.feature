Feature: Single instance enforcement

  Background:
    Given a clean working directory
    And the mock gateway is installed as "gateway"
    And the launcher is in prebuilt mode
    And NATS is skipped

  Scenario: Only one launcher can run at a time
    Given the launcher starts
    And the gateway PID file exists
    When a second launcher instance is started
    Then the second instance exits with a non-zero code
    And the error output contains "already running"

  Scenario: Launcher can restart after clean shutdown
    Given the launcher starts
    And the gateway PID file exists
    When the launcher is stopped
    Then a new launcher instance can start successfully
