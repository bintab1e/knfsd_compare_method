from compare_method.runtime_probe import (
    _gss_init_request,
    _parse_sender_output,
    _setclientid_request,
    _verify_request,
    _write_request_batch,
)


def test_bounded_rpc_requests_have_record_markers() -> None:
    for builder in (_setclientid_request, _verify_request, _gss_init_request):
        request = builder(0x12345678, 64)
        record_size = int.from_bytes(request[:4], "big")
        assert record_size & 0x80000000
        assert record_size & 0x7FFFFFFF == len(request) - 4
        assert request[4:8] == b"\x12\x34\x56\x78"


def test_static_sender_batch_and_result_parser(tmp_path) -> None:
    request = _verify_request(0x12345678, 8)
    batch = tmp_path / "requests.bin"
    _write_request_batch(batch, [(0x12345678, request)])
    assert int.from_bytes(batch.read_bytes()[:4], "big") == 1

    result = _parse_sender_output(
        "0\t12345678\t%d\t4\t0\t2500\t01020304\n" % len(request),
        [(0x12345678, request)],
    )
    assert result[0]["response_bytes"] == 4
    assert result[0]["elapsed_seconds"] == 0.0025
    assert result[0]["error"] is None
