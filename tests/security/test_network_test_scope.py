"""VER-002: keep real loopback TCP tests out of the hermetic unit target."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
LIVE_TESTS = (
    "TcpServer bind and listen on ephemeral port",
    "TcpServer + TcpTransport connect + send + recv roundtrip",
    "TcpServer + TcpClient full roundtrip via TcpClient wrapper",
    "FramedReader readFrameFromTransport pulls from transport",
    "TcpClient reconnectIfNeeded fails when no listener",
    "End-to-end: 2 nodes exchange messages via real TCP",
    "TcpTransport detects peer disconnect on recv",
    "TcpTransport asTransport vtable works through fc.Transport interface",
    "TcpServer bound address format",
)


def test_real_socket_tests_require_explicit_network_integration_opt_in():
    source = (ROOT / "src/federation/federation_tcp.zig").read_text(encoding="utf-8")
    assert '"AEGIS_TCP_INTEGRATION"' in source
    assert "return error.SkipZigTest" in source

    for name in LIVE_TESTS:
        marker = f'test "{name}" {{\n    try requireNetworkIntegration();'
        assert marker in source, f"real-socket test is not opt-in: {name}"


def test_real_socket_target_is_separate_and_sets_opt_in_marker():
    build = (ROOT / "build.zig").read_text(encoding="utf-8")
    assert 'b.step("test-network-integration"' in build
    assert 'b.path("src/tests/federation/federation_tcp.zig")' in build
    assert 'setEnvironmentVariable("AEGIS_TCP_INTEGRATION", "1")' in build
