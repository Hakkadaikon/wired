# MoqtVerCtl counterexample F-A1 (TLC: MC_split.cfg, logs/split.out)
# Spec:  draft-ietf-moq-transport-22 6.3 / 9.1 (19 3.3 / 10.3): the client's
#        control stream begins with SETUP (Type 0x2F00, a 2-byte vi64 AF 00).
#        RFC 9000 2.2: STREAM frame boundaries are not preserved on delivery.
# Code:  src/app/moqt/run/moqtrun.c @206c185
#        :5945 moqtrun_fresh_uni_ctl  -- classifies the FIRST DELIVERY only;
#              moqdata_classify on 1 byte = INSUFFICIENT != CONTROL
#        :5963 moqtrun_hold_gate      -- token session held until established
#        :6082 moqtrun_dispatch_data_stream hold_has -> later bytes held too
#        :6318 moqtrun_bidi_is_setup  -- same pattern on a SETUP-first bidi
# Result: the session never establishes; requests are held until the hold
#         log overflows (EXCESSIVE_LOAD reset). Self-loopback never splits.

Feature: Client control stream delivered in fragments

  Background:
    Given a hub with a session SESS_A negotiated with WT subprotocol "moqt-22"
    And the hub has opened its uni control stream with SETUP

  Scenario: SETUP Type varint split across two uni deliveries
    When the client's uni stream 2 delivers the single byte 0xAF
    And the client's bidi stream 0 delivers a SUBSCRIBE request
    And the client's uni stream 2 delivers 0x00 followed by the SETUP Length and options
    Then the session is Established
    And the SUBSCRIBE on stream 0 is answered
    And no session close is issued

  Scenario: SETUP-first bidi split inside its Type varint
    When the client's bidi stream 0 delivers the single byte 0xAF
    And the client's bidi stream 0 delivers 0x00 followed by the SETUP Length and options
    Then the session is Established
    And stream 0 is the client control stream, not a request stream

  Scenario: split after the whole Type varint still works (regression guard)
    # Already green today (adopted on classify, reassembled in peer_ctl_asm);
    # keep it so the fix for the two scenarios above does not regress it.
    When the client's uni stream 2 delivers the bytes 0xAF 0x00
    And the client's uni stream 2 delivers the SETUP Length and options
    Then the session is Established
    And exactly one SETUP is accepted
