# MoqtRawConn counterexamples -> acceptance specs (ledger 13-2).
# Model: tasks/loopeng/moqt/MoqtRawConn/MoqtRawConn.tla (+ wtroute/MoqtWtRoute.tla)
# Code read at 7e7a0dd (main tree, read-only).
# Spec: draft-ietf-moq-transport-18 3.1.4/3.3/3.5/10.3.1.1-2,
#       -19 3.1.5/3.3/3.5/10.3.1.1-2, -22 6.2.2/6.3/6.6/9.1.1-2;
#       RFC 9000 10.2 / 10.2.1 / 19.19.
# Every scenario names the TLC log of the trace it was derived from and the
# test id (plan section 7) that must pin it.

Feature: Raw-QUIC MoQT session lifecycle on the wired server

  Background:
    Given a wired server with raw_alpns "moqt-22 moqt-19 moqt-18" and h3 enabled
    And the MoQT hub registered as raw_on_session / wt_on_session / wt_on_stream_data / wt_on_session_close

  # ---- Mutation M1: logs/mut_late_session.out (SessBeforeData) -> T-E8 ----
  Scenario: no stream byte reaches the hub before raw_on_session
    Given a client offering ALPN ["moqt-18", "h3"]
    When the client sends its control stream (uni id 2, "SETUP" with PATH "/") before the server has confirmed the handshake
    And the handshake is confirmed in the same datagram
    Then raw_on_session fires exactly once for that connection
    And it fires before the first wt_on_stream_data for that connection
    And the bytes of uni stream 2 are delivered whole, starting with the SETUP type

  # ---- Mutation M2: logs/mut_wt_path.out + mut_wt_path_live.out (PathRule, EstablishLive) -> T-F2 ----
  Scenario Outline: SETUP PATH/AUTHORITY verdict depends on the transport
    Given a session on transport <transport>
    When the client SETUP carries <option>
    Then the session outcome is <outcome>

    Examples:
      | transport | option                              | outcome                                 |
      | raw       | PATH "/" and AUTHORITY "relay:4443" | Established                             |
      | raw       | PATH "moq" (not path-abempty)       | CONNECTION_CLOSE 0x1d code 0x9          |
      | raw       | AUTHORITY ":443" (empty host)       | CONNECTION_CLOSE 0x1d code 0x1A         |
      | raw       | PATH refused by the policy hook     | CONNECTION_CLOSE 0x1d code 0x8          |
      | wt        | PATH "/"                            | CLOSE_WEBTRANSPORT_SESSION code 0x8     |
      | wt        | AUTHORITY "relay:4443"              | CLOSE_WEBTRANSPORT_SESSION code 0x19    |

  # ---- Mutation M3: logs/mut_h3ctrl.out (NoH3OnRaw) -> T-E1 ----
  Scenario: a raw connection never opens HTTP/3 control streams
    Given a client offering ALPN ["moqt-18", "h3"]
    When the handshake is confirmed
    Then the server sends no STREAM frame carrying an H3 control-stream type or SETTINGS
    And no QPACK encoder/decoder stream is opened
    And a server shutdown sends no HTTP/3 GOAWAY on that connection
    And the server's first uni stream is id 3 and carries the server SETUP

  # ---- Mutation M4: logs/mut_double_close.out (CloseOnce) -> T-E8 ----
  Scenario: a hub close on raw fires wt_on_session_close exactly once
    Given an established raw session whose client SETUP carried a malformed PATH
    When the hub closes the session with MALFORMED_PATH 0x9
    Then the server sends CONNECTION_CLOSE type 0x1d with error code 0x9
    And wt_on_session_close fires once for that session
    When the connection slot is later freed by the idle sweep
    Then wt_on_session_close does not fire again
    And a new connection that reuses the slot gets a fresh raw_on_session before any of its data

  # ---- Real discrepancy D2: logs/shipped_rawclose.out, shipped_appclose.out,
  #      shipped_appclose_live.out (NoDataAfterClose, CloseLive).
  # Today srvrun_send_app_close (srvrun.c:2038) only sends the frame. The
  # connection stays up, its WT sessions stay active, later peer packets are
  # still offered/delivered to the app, and wt_on_session_close waits for the
  # idle sweep (30 s, restarted by every received packet) or a peer
  # CONNECTION_CLOSE. Already live on the WT path for every violation close
  # (bad qsid 2478, H3_FRAME_ERROR 3884/3918, AEAD limit, reset flood, drained
  # shutdown 10186); plan S5 reuses it for the raw hub close.
  Scenario: after the server's CONNECTION_CLOSE no more data reaches the hub (raw hub close)
    Given an established raw session
    And the client has sent two stream chunks, of which the hub has received one
    When the hub calls close_session with NO_ERROR
    Then the server sends CONNECTION_CLOSE type 0x1d with error code 0x0
    And wt_on_session_close fires in the same step, before the step returns
    And the second chunk is never delivered to wt_on_stream_data
    And no STREAM frame is sent on that connection afterwards
    And any later packet from the client is answered only with CONNECTION_CLOSE (RFC 9000 10.2.1)

  Scenario: a connection-level violation close ends the WT session immediately
    Given an established WebTransport session on an h3 connection
    When the client sends a DATAGRAM with a truncated quarter stream id
    Then the server sends CONNECTION_CLOSE with H3_DATAGRAM_ERROR
    And wt_on_session_close fires for the session in the same step
    And a WT stream chunk the client sent afterwards is not delivered to wt_on_stream_data

  Scenario: a raw hub close never puts a second, different CONNECTION_CLOSE on the wire
    Given an established raw session
    And a connection-level violation has already closed the connection with a transport error
    When the hub, still unaware, calls close_session with PROTOCOL_VIOLATION
    Then no second CONNECTION_CLOSE carrying 0x3 is sent

  # ---- Real discrepancy D1 (WT path, does not apply to the single raw
  #      session): wtroute/logs/shipped.out (DeliverToOwner).
  # srvrun_offer_wt[_uni]_slot records slot->wt_session_slot; the delivery in
  # srvrun_offer_and_deliver_wt[_uni]_slot recomputes the first active slot
  # (srvrun.c:2456 / 2682) instead of using it.
  Scenario: WT stream bytes stay with the session they were associated with
    Given an h3 connection with WT flow control enabled
    And WT session A in slot 0 and WT session B in slot 1
    When session A is closed
    And the client opens WT bidi stream 8 and its first chunk is associated with session B
    And a new Extended CONNECT establishes session C in slot 0
    And the next chunk of stream 8 arrives
    Then that chunk is delivered with session B's pointer, not session C's
    And closing session B resets stream 8

  # ---- Design note D3 (not a violation, from the step order) ----
  Scenario: client SETUP coalesced with the client Finished is delivered without waiting for another packet
    Given a client offering ALPN ["moqt-19"]
    When one UDP datagram carries the client Finished and a 1-RTT STREAM frame on uni id 2 with the SETUP
    Then raw_on_session and then wt_on_stream_data for stream 2 both fire while that datagram is processed
