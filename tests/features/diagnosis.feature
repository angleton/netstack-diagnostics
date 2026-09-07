Feature: Bottom-up packet diagnosis
  As a network engineer troubleshooting from the wire upward
  I want captured packets analyzed layer by layer (L2 -> L3 -> L4)
  So that I can attribute a failure to the correct layer without a GUI tool

  Scenario: A healthy TCP packet is reported healthy
    Given a packet capture containing a "healthy_tcp" packet
    When the capture is analyzed
    Then the diagnosis is "Healthy"

  Scenario: A corrupted IPv4 header checksum is caught at layer 3
    Given a packet capture containing a "bad_ip_checksum" packet
    When the capture is analyzed
    Then the diagnosis is "Layer3ChecksumInvalid"

  Scenario: An expired TTL is caught at layer 3
    Given a packet capture containing a "ttl_expired" packet
    When the capture is analyzed
    Then the diagnosis is "Layer3TtlExpired"

  Scenario: A TCP reset is caught at layer 4
    Given a packet capture containing a "tcp_reset" packet
    When the capture is analyzed
    Then the diagnosis is "Layer4ConnectionReset"

  Scenario: A healthy UDP datagram is accepted without TCP connection state
    Given a packet capture containing a "healthy_udp" packet
    When the capture is analyzed
    Then the diagnosis is "Healthy"

  Scenario: A corrupted UDP checksum is caught at layer 4
    Given a packet capture containing a "bad_udp_checksum" packet
    When the capture is analyzed
    Then the diagnosis is "Layer4ChecksumInvalid"

  Scenario: An ICMP destination unreachable message is recognized
    Given a packet capture containing a "icmp_port_unreachable" packet
    When the capture is analyzed
    Then the diagnosis is "Layer4DestinationUnreachable"

  Scenario: An ICMP time exceeded message is recognized
    Given a packet capture containing a "icmp_time_exceeded" packet
    When the capture is analyzed
    Then the diagnosis is "Layer3TimeExceededEnRoute"

  Scenario: A truncated Ethernet frame cannot be parsed
    Given a packet capture containing a "truncated_frame" packet
    When the capture is analyzed
    Then the diagnosis is "Layer2Malformed"
