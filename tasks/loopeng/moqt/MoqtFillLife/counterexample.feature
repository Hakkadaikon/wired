# MoqtFillLife counterexamples (TLC: MC_omitted / MC_omitted_abs /
# MC_malformed / MC_capacity; logs/*.out)
# Spec: draft-ietf-moq-transport-22 3.4 (l.1546-1560), 3.4.1 (l.1607-1615),
#       9.20.15 (l.5476-5484), 9.20 (l.5084-5087)
# Code: src/app/moqt/run/moqtrun.c @206c185, src/app/moqt/fetch/moqfetch.c

Feature: Draft-22 fill fetch stream lifecycle

  Background:
    Given a draft-22 session B subscribed through the hub to track "alice/v"
    And the hub's cache holds groups 0, 1 and 2 of "alice/v" (Largest Object in group 2)

  # F-B1 -- moqfetch.c:285 moqfetch_fill_filter_of + moqtrun.c:2342
  # moqtrun_fill_rl: an ABSENT LOCATION_FILTER is folded into "no filter"
  # (whole track); 3.4 says the subscription's Location filter applies.
  Scenario: Omitted fill filter under a Next Object subscription opens no fill
    When B sends SUBSCRIBE with LOCATION_FILTER type 0x05 (Next Object)
    And the SUBSCRIBE carries FILL_PARAMETERS with no LOCATION_FILTER inside
    Then B receives SUBSCRIBE_OK
    And the hub opens no fill fetch stream

  Scenario: Omitted fill filter inherits an AbsoluteStart subscription filter
    When B sends SUBSCRIBE with LOCATION_FILTER type 0x02 StartGroup 1 StartObject 0
    And the SUBSCRIBE carries FILL_PARAMETERS with no LOCATION_FILTER inside
    Then the hub opens one fill fetch stream whose FETCH_HEADER Request ID is the SUBSCRIBE's
    And the first Object on it is in group 1
    And no Object of group 0 is sent on it

  Scenario: Explicit 0x00 fill filter still fills the whole track (Q-02, regression guard)
    When B sends SUBSCRIBE with LOCATION_FILTER type 0x05 (Next Object)
    And the SUBSCRIBE carries FILL_PARAMETERS with LOCATION_FILTER type 0x00
    Then the hub opens one fill fetch stream starting in group 0

  # F-B2 -- moqtrun.c:2391 moqtrun_fill_from_param returns silently after
  # SUBSCRIBE_OK was queued at :1407.
  Scenario: Malformed FILL_PARAMETERS closes the session
    When B sends SUBSCRIBE whose FILL_PARAMETERS value holds an unknown parameter type
    Then the hub closes B's session with PROTOCOL_VIOLATION
    And no SUBSCRIBE_OK is sent for that request

  # F-B3 -- moqtrun.c:2307 moqtrun_fill_wait_put "if (!w) return;" (ruled
  # 2026-10-04; the ruling's premise "refused at acceptance" does not hold:
  # SUBSCRIBE_OK :1407 / REQUEST_OK :2830 precede the placement).
  Scenario: A fill accepted while both fill tables are full is not silently lost
    Given every fetches[] slot and every fetch_waits[] slot is occupied by a held fill
    When B sends SUBSCRIBE with FILL_PARAMETERS LOCATION_FILTER type 0x02 StartGroup 0
    Then either B receives REQUEST_ERROR for that SUBSCRIBE
    Or the hub eventually opens a fill fetch stream for it and resets it with INTERNAL_ERROR
