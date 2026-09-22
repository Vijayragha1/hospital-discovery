"""Apply per-child POSIX resource limits, then exec a fixed supervisor command."""
import math
import os
import resource
import signal
import sys


def address_space_limit(binary):
    # HotSpot plus the amd64 translation runtime needs extra virtual address
    # reservations before main(). The fixed PDF inspector JVM still has a
    # 128 MiB heap; the parser container independently caps physical memory.
    # Every other native parser child retains the smaller address-space bound.
    return (2 if os.path.basename(binary) == "java" else 1) * 1024 * 1024 * 1024


def main():
    try:
        # The parser deployment is Linux. Fail closed on systems without the
        # address-space limit rather than claiming equivalent confinement.
        if not sys.platform.startswith("linux"):
            return 125
        cpu, file_bytes = float(sys.argv[1]), int(sys.argv[2])
        command = sys.argv[3:]
        if not command or not 0 < cpu <= 60 or not 0 < file_bytes <= 128 * 1024 * 1024:
            return 125
        signal.pthread_sigmask(signal.SIG_SETMASK, set())
        os.umask(0o077)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
        resource.setrlimit(resource.RLIMIT_FSIZE, (file_bytes, file_bytes))
        seconds = max(1, math.ceil(cpu))
        resource.setrlimit(resource.RLIMIT_CPU, (seconds, seconds + 1))
        address_space = address_space_limit(command[0])
        resource.setrlimit(resource.RLIMIT_AS, (address_space, address_space))
        os.execv(command[0], command)
    except Exception:
        return 125


if __name__ == "__main__":
    raise SystemExit(main())
