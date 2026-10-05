# MoqtXRelay counterexample F-C1 (TLC: MC_shipped_p22_a19.cfg,
# logs/shipped_p22_a19.out)
# Spec: draft-ietf-moq-transport-19 10.2 (l.3332-3335) -- "An endpoint that
#       receives an unknown Message Parameter MUST close the session with
#       PROTOCOL_VIOLATION"; same rule draft-18 10.2 (l.3041-3044) and
#       draft-22 9.20 (l.5084-5087).
# Code: src/app/moqt/run/moqtrun.c @206c185
#       :1739 moqtrun_handle_subscribe   decode failure -> return (silent)
#       siblings: :910 PUBLISH, :2602 TRACK_STATUS, :3277 PUBLISH_NAMESPACE /
#       SUBSCRIBE_NAMESPACE, :3496 SUBSCRIBE_TRACKS
#       correct reference: :2546 moqtrun_handle_fetch (closes)

Feature: Cross-version relay refuses features the sender's draft lacks

  Background:
    Given a draft-22 publisher session P has PUBLISHed track "alice/v" to the hub
    And the hub's cache holds groups 0 and 1 of "alice/v"

  Scenario: draft-19 subscriber sends a draft-22-only FILL_PARAMETERS
    Given a subscriber session A negotiated with WT subprotocol "moqt-19"
    When A sends SUBSCRIBE for "alice/v" carrying FILL_PARAMETERS (0x23)
    Then the hub closes A's session with PROTOCOL_VIOLATION
    And no SUBSCRIBE_OK and no fill fetch stream are sent to A

  Scenario: draft-18 subscriber sends a Range Filter parameter
    Given a subscriber session A negotiated with WT subprotocol "moqt-18"
    When A sends SUBSCRIBE for "alice/v" carrying SUBGROUP_FILTER (0x25)
    Then the hub closes A's session with PROTOCOL_VIOLATION

  Scenario Outline: other request types with an out-of-draft parameter close too
    Given a subscriber session A negotiated with WT subprotocol "<token>"
    When A opens a request stream with <message> carrying parameter <param>
    Then the hub closes A's session with PROTOCOL_VIOLATION

    Examples:
      | token   | message             | param                    |
      | moqt-19 | PUBLISH             | INCLUDE_PROPERTIES 0x35  |
      | moqt-19 | TRACK_STATUS        | FILL_PARAMETERS 0x23     |
      | moqt-18 | SUBSCRIBE_TRACKS    | SUBGROUP_FILTER 0x25     |
      | moqt-19 | SUBSCRIBE_NAMESPACE | FILL_PARAMETERS 0x23     |

  Scenario: the same SUBSCRIBE from a draft-22 subscriber is served (regression guard)
    Given a subscriber session B negotiated with WT subprotocol "moqt-22"
    When B sends SUBSCRIBE for "alice/v" carrying FILL_PARAMETERS with LOCATION_FILTER type 0x00
    Then B receives SUBSCRIBE_OK encoded for draft-22
    And B receives one fill fetch stream
