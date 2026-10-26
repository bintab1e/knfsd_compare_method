from __future__ import annotations

import argparse
import gzip
import importlib.util
import json
import os
import re
import shlex
import struct
import subprocess
import time
from pathlib import Path
from typing import Any

import yaml

from .common import repo_root, sha256_bytes, sha256_file, write_json


OP_SETCLIENTID = 35
OP_VERIFY = 37


def _u32(value: int) -> bytes:
    return struct.pack(">I", value)


def _opaque(value: bytes) -> bytes:
    return _u32(len(value)) + value + b"\0" * ((-len(value)) % 4)


def _auth_sys() -> bytes:
    body = _u32(0x544F4241) + _opaque(b"tobabz-lab") + _u32(0) + _u32(0) + _u32(0)
    return _u32(1) + _opaque(body)


def _auth_none() -> bytes:
    return _u32(0) + _u32(0)


def _rpc_call(xid: int, procedure: int, credential: bytes, body: bytes) -> bytes:
    call = b"".join(
        [
            _u32(xid),
            _u32(0),
            _u32(2),
            _u32(100003),
            _u32(4),
            _u32(procedure),
            credential,
            _auth_none(),
            body,
        ]
    )
    return _u32(0x80000000 | len(call)) + call


def _setclientid_request(xid: int, payload_size: int) -> bytes:
    netid = (b"tcp" + b"N" * payload_size)[:payload_size]
    address = (b"10.0.2.2.1.1" + b"A" * payload_size)[:payload_size]
    operation = b"".join(
        [
            _u32(OP_SETCLIENTID),
            b"TOBABZ01",
            _opaque(b"round1-client"),
            _u32(0x40000001),
            _opaque(netid),
            _opaque(address),
            _u32(1),
        ]
    )
    compound = _opaque(b"round1") + _u32(0) + _u32(1) + operation
    return _rpc_call(xid, 1, _auth_sys(), compound)


def _verify_request(xid: int, payload_size: int) -> bytes:
    operation = _u32(OP_VERIFY) + _u32(0) + _opaque(b"V" * payload_size)
    compound = _opaque(b"round1") + _u32(0) + _u32(1) + operation
    return _rpc_call(xid, 1, _auth_sys(), compound)


def _gss_init_request(xid: int, payload_size: int) -> bytes:
    credential_body = _u32(1) + _u32(1) + _u32(0) + _u32(1) + _opaque(b"")
    credential = _u32(6) + _opaque(credential_body)
    return _rpc_call(xid, 0, credential, _opaque(b"G" * payload_size))


REQUESTS = {
    "nfsd4_decode_setclientid": _setclientid_request,
    "nfsd4_decode_verify": _verify_request,
    "svcauth_gss_legacy_init": _gss_init_request,
}

PROBES = {
    "nfsd4_decode_setclientid": "round1_setclientid",
    "nfsd4_decode_verify": "round1_verify",
    "svcauth_gss_legacy_init": "round1_gss_init",
}

GUEST_SENDER = r'''#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

struct item {
    uint32_t index, xid, length;
    unsigned char *request;
    unsigned char response[65536];
    ssize_t response_length;
    int error_number;
    long elapsed_us;
    const char *host;
    int port;
    pthread_barrier_t *barrier;
};

static int read_u32(FILE *file, uint32_t *value) {
    uint32_t encoded;
    if (fread(&encoded, sizeof(encoded), 1, file) != 1) return -1;
    *value = ntohl(encoded);
    return 0;
}

static void *send_one(void *opaque) {
    struct item *item = opaque;
    struct timespec start, end;
    struct sockaddr_in address;
    struct timeval timeout = {.tv_sec = 10, .tv_usec = 0};
    size_t offset = 0;
    int fd = -1;
    clock_gettime(CLOCK_MONOTONIC, &start);
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) item->error_number = errno;
    if (!item->error_number) {
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_port = htons((uint16_t)item->port);
        if (inet_pton(AF_INET, item->host, &address.sin_addr) != 1 ||
            connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0)
            item->error_number = errno ? errno : EINVAL;
    }
    pthread_barrier_wait(item->barrier);
    while (!item->error_number && offset < item->length) {
        ssize_t sent = send(fd, item->request + offset, item->length - offset, 0);
        if (sent <= 0) item->error_number = errno ? errno : EIO;
        else offset += (size_t)sent;
    }
    if (!item->error_number) {
        item->response_length = recv(fd, item->response, sizeof(item->response), 0);
        if (item->response_length < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) item->response_length = 0;
            else {
                item->error_number = errno;
                item->response_length = 0;
            }
        }
    }
    if (fd >= 0) close(fd);
    clock_gettime(CLOCK_MONOTONIC, &end);
    item->elapsed_us = (end.tv_sec - start.tv_sec) * 1000000L +
                       (end.tv_nsec - start.tv_nsec) / 1000L;
    return NULL;
}

int main(int argc, char **argv) {
    FILE *file;
    struct item *items;
    pthread_t *threads;
    uint32_t count, index;
    int concurrency, offset;
    if (argc != 5) return 2;
    file = fopen(argv[1], "rb");
    if (!file || read_u32(file, &count) || count == 0 || count > 10000) return 3;
    concurrency = atoi(argv[4]);
    if (concurrency < 1 || concurrency > 128) return 4;
    items = calloc(count, sizeof(*items));
    threads = calloc((size_t)concurrency, sizeof(*threads));
    if (!items || !threads) return 5;
    for (index = 0; index < count; index++) {
        items[index].index = index;
        items[index].host = argv[2];
        items[index].port = atoi(argv[3]);
        if (read_u32(file, &items[index].xid) || read_u32(file, &items[index].length) ||
            items[index].length == 0 || items[index].length > 1048576) return 6;
        items[index].request = malloc(items[index].length);
        if (!items[index].request ||
            fread(items[index].request, items[index].length, 1, file) != 1) return 7;
    }
    fclose(file);
    for (offset = 0; offset < (int)count; offset += concurrency) {
        int batch = concurrency;
        pthread_barrier_t barrier;
        if (offset + batch > (int)count) batch = (int)count - offset;
        pthread_barrier_init(&barrier, NULL, (unsigned)batch);
        for (int worker = 0; worker < batch; worker++) {
            items[offset + worker].barrier = &barrier;
            pthread_create(&threads[worker], NULL, send_one, &items[offset + worker]);
        }
        for (int worker = 0; worker < batch; worker++) pthread_join(threads[worker], NULL);
        pthread_barrier_destroy(&barrier);
    }
    for (index = 0; index < count; index++) {
        printf("%u\t%08x\t%u\t%zd\t%d\t%ld\t", items[index].index,
               items[index].xid, items[index].length, items[index].response_length,
               items[index].error_number, items[index].elapsed_us);
        for (ssize_t byte = 0; byte < items[index].response_length; byte++)
            printf("%02x", items[index].response[byte]);
        putchar('\n');
        free(items[index].request);
    }
    free(threads);
    free(items);
    return 0;
}
'''


def _load_bootstrap(repo: Path):
    path = repo / "external" / "knfsd-syzkaller" / "tools" / "bootstrap-kcov-env.py"
    spec = importlib.util.spec_from_file_location("knfsd_runtime_bootstrap", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import runtime bootstrap: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _guest(vm: Any, command: str, timeout: int = 120) -> str:
    return vm.guest(command, timeout=timeout)


def _setup_probes(vm: Any) -> list[str]:
    lines = [
        "set -eu",
        "mountpoint -q /sys/kernel/tracing || mount -t tracefs nodev /sys/kernel/tracing",
        "cd /sys/kernel/tracing",
        "echo 0 > tracing_on",
        "echo > trace",
        "echo > kprobe_events",
    ]
    for function, name in PROBES.items():
        lines.append(f"echo 'p:round1/{name} {function}' >> kprobe_events")
        lines.append(f"echo 1 > events/round1/{name}/enable")
    lines.extend(["echo 1 > tracing_on", "dmesg -c >/tmp/round1.dmesg.before || true"])
    _guest(vm, "; ".join(lines))
    return list(PROBES)


def _write_request_batch(path: Path, requests: list[tuple[int, bytes]]) -> None:
    with path.open("wb") as handle:
        handle.write(_u32(len(requests)))
        for xid, request in requests:
            handle.write(_u32(xid))
            handle.write(_u32(len(request)))
            handle.write(request)


def _build_guest_sender(output: Path) -> Path:
    source = output / "guest_rpc_sender.c"
    binary = output / "guest_rpc_sender"
    source.write_text(GUEST_SENDER, encoding="utf-8")
    completed = subprocess.run(
        ["cc", "-O2", "-static", "-pthread", str(source), "-o", str(binary)],
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode:
        raise RuntimeError(f"static guest sender build failed: {completed.stderr[-2000:]}")
    return binary


def _parse_sender_output(
    output: str, requests: list[tuple[int, bytes]]
) -> list[dict[str, Any]]:
    parsed: dict[int, dict[str, Any]] = {}
    for line in output.splitlines():
        fields = line.split("\t", 6)
        if len(fields) != 7:
            continue
        index = int(fields[0])
        response = bytes.fromhex(fields[6]) if fields[6] else b""
        error_number = int(fields[4])
        request = requests[index][1]
        parsed[index] = {
            "xid": fields[1],
            "request_sha256": sha256_bytes(request),
            "request_bytes": int(fields[2]),
            "response_sha256": sha256_bytes(response),
            "response_bytes": int(fields[3]),
            "error": f"errno {error_number}: {os.strerror(error_number)}" if error_number else None,
            "elapsed_seconds": round(int(fields[5]) / 1_000_000, 4),
        }
    if len(parsed) != len(requests):
        raise RuntimeError(
            f"guest sender returned {len(parsed)} result rows for {len(requests)} requests"
        )
    return [parsed[index] for index in range(len(requests))]


def _jobs(repo: Path, sanitizer: str, jobs_root: Path | None = None) -> list[dict[str, Any]]:
    root = jobs_root or repo / "validation" / "jobs"
    paths = sorted(root.glob(f"CANDIDATE-*/{sanitizer}.json"))
    return [json.loads(path.read_text(encoding="utf-8")) | {"job_path": str(path)} for path in paths]


def _target_function(job: dict[str, Any]) -> str | None:
    for function in REQUESTS:
        if function in job.get("target_functions", []):
            return function
    return None


def run_probe(
    repo: Path,
    sanitizer: str,
    output: Path,
    payload_size: int,
    jobs_root: Path | None = None,
) -> dict[str, Any]:
    config = yaml.safe_load((repo / "config" / "runtime-harness.yaml").read_text(encoding="utf-8"))
    jobs = _jobs(repo, sanitizer, jobs_root)
    if not jobs:
        raise ValueError(f"no {sanitizer} jobs found")
    profile = config["profiles"][sanitizer]
    image = repo / "runtime" / "knfsd-v7.3" / "images" / "bookworm-kcov-fresh.qcow2"
    kernel = repo / profile["bzimage"]
    vmlinux = repo / profile["vmlinux"]
    key = repo / config["environment"]["ssh_key"]
    manifest_path = repo / config["environment"]["manifest"]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    bootstrap = _load_bootstrap(repo)
    vm = bootstrap.VM(image, kernel, key, 240, "4.0")
    output.mkdir(parents=True, exist_ok=True)
    sender_binary = _build_guest_sender(output)
    sent: dict[str, list[dict[str, Any]]] = {name: [] for name in REQUESTS}
    started = time.monotonic()
    try:
        vm.start()
        state = _guest(vm, "systemctl is-active frozen-phase9-fixture.service || true").strip()
        if state != "active":
            raise RuntimeError(f"fixture service is {state}")
        fixture_root = _guest(vm, "ls -d /tmp/frozen-phase9.* | head -n 1").strip()
        client_pid = int(_guest(vm, f"cat {shlex.quote(fixture_root)}/lane0/client0.pid").strip())
        vm.put(sender_binary, "/tmp/round1-rpc-sender")
        _guest(vm, "chmod 0755 /tmp/round1-rpc-sender")
        _setup_probes(vm)
        xid = 0x4B4E0000
        for function, builder in REQUESTS.items():
            matching = [job for job in jobs if _target_function(job) == function]
            if not matching:
                continue
            runs = max(job["execution"]["max_runs"] for job in matching)
            concurrency = max(job["execution"]["concurrency"] for job in matching)
            requests = [(xid + index, builder(xid + index, payload_size)) for index in range(runs)]
            request_path = output / f"requests-{function}.bin"
            _write_request_batch(request_path, requests)
            remote_path = f"/tmp/round1-{function}.bin"
            vm.put(request_path, remote_path)
            command = (
                f"nsenter -t {client_pid} -n -- /tmp/round1-rpc-sender "
                f"{remote_path} 10.89.0.1 2049 {concurrency}"
            )
            sender_output = _guest(vm, command, timeout=max(180, runs * 15))
            sent[function] = _parse_sender_output(sender_output, requests)
            xid += runs + 0x100

        trace = _guest(
            vm,
            "cd /sys/kernel/tracing; echo 0 > tracing_on; cat trace",
            timeout=180,
        )
        dmesg = _guest(vm, "dmesg -c || true", timeout=180)
    finally:
        vm.stop()

    trace_path = output / "trace.txt.gz"
    with gzip.open(trace_path, "wt", encoding="utf-8") as handle:
        handle.write(trace)
    dmesg_path = output / "dmesg.log"
    dmesg_path.write_text(dmesg, encoding="utf-8")

    hits = {
        function: len(re.findall(rf"\b{re.escape(name)}:", trace))
        for function, name in PROBES.items()
    }
    marker = "KASAN" if sanitizer == "kasan" else "KCSAN"
    signals = [line for line in dmesg.splitlines() if marker in line or "data-race" in line]
    results = []
    for job in jobs:
        function = _target_function(job)
        required = job["execution"]["max_runs"]
        reached = hits.get(function or "", 0)
        if signals:
            label = "sanitizer_signal"
        elif reached >= required:
            label = "no_signal_after_100" if sanitizer == "kcsan" and required == 100 else "no_signal"
        elif function is None:
            label = "harness_gap"
        else:
            label = "unreached"
        results.append(
            {
                "candidate_id": job["candidate_id"],
                "job_path": job["job_path"],
                "target_function": function,
                "attempted_runs": len(sent.get(function or "", [])),
                "effective_target_reached_runs": reached,
                "required_effective_runs": required,
                "sanitizer_signals": signals,
                "terminal_label": label,
            }
        )

    report = {
        "schema_version": "1.0.0",
        "sanitizer": sanitizer,
        "kernel_ref": "v7.3",
        "runtime_manifest_sha256": sha256_file(manifest_path),
        "runtime_manifest_status": manifest.get("status"),
        "image_sha256": sha256_file(image),
        "kernel_sha256": sha256_file(kernel),
        "vmlinux_sha256": sha256_file(vmlinux),
        "transport": {
            "origin": "qemu-guest:lane0-client0-netns (10.89.0.2)",
            "destination": "qemu-guest:lane0-knfsd-via-relay (10.89.0.1:2049/tcp)",
            "remote_network_path": True,
        },
        "payload_size": payload_size,
        "elapsed_seconds": round(time.monotonic() - started, 2),
        "probe_hits": hits,
        "requests": sent,
        "trace_path": str(trace_path),
        "trace_sha256": sha256_file(trace_path),
        "dmesg_path": str(dmesg_path),
        "dmesg_sha256": sha256_file(dmesg_path),
        "results": results,
    }
    write_json(output / "result.json", report)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Run bounded remote RPC probes in the KNFSd QEMU lab.")
    parser.add_argument("--repo", type=Path, default=repo_root())
    parser.add_argument("--sanitizer", choices=("kasan", "kcsan"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--payload-size", type=int, default=65536)
    parser.add_argument("--jobs-root", type=Path)
    args = parser.parse_args()
    if not 1 <= args.payload_size <= 262144:
        raise SystemExit("--payload-size must be between 1 and 262144")
    report = run_probe(
        args.repo.resolve(),
        args.sanitizer,
        args.output.resolve(),
        args.payload_size,
        args.jobs_root.resolve() if args.jobs_root else None,
    )
    print(json.dumps({"sanitizer": args.sanitizer, "probe_hits": report["probe_hits"], "results": report["results"]}, indent=2))


if __name__ == "__main__":
    main()
