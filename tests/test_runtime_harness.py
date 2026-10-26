from compare_method.runtime_harness import _manifest_kernel_ref


def test_manifest_kernel_ref_reads_current_nested_shape() -> None:
    assert _manifest_kernel_ref({"kernel": {"ref": "v7.3"}}) == "v7.3"


def test_manifest_kernel_ref_keeps_legacy_compatibility() -> None:
    assert _manifest_kernel_ref({"kernel_ref": "v7.3"}) == "v7.3"
