import asyncio
import ipaddress
import os
import random
import ssl
import time
import urllib.request
from pathlib import Path


def read_env(name: str, default: str) -> str:
    v = os.getenv(name)
    return v.strip() if v is not None and str(v).strip() else default


def fetch_lines(url: str) -> list[str]:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        text = resp.read().decode("utf-8", errors="replace")
    return [line.strip() for line in text.splitlines() if line.strip()]


def pick_random_ipv4_from_cidr(cidr: str) -> str:
    net = ipaddress.ip_network(cidr, strict=False)
    if net.num_addresses <= 2:
        return str(net.network_address)
    start = int(net.network_address) + 1
    end = int(net.broadcast_address) - 1
    return str(ipaddress.IPv4Address(random.randint(start, end)))


async def probe_tls(ip: str, port: int, server_name: str, timeout: float) -> float | None:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    start = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx, server_hostname=server_name),
            timeout=timeout,
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return (time.perf_counter() - start) * 1000.0
    except Exception:
        return None


async def run() -> None:
    target_host = read_env("TARGET_HOST", "")
    if not target_host:
        raise SystemExit("Missing TARGET_HOST")

    ports_raw = read_env("PORTS", "443,2053,2083,2087,2096,8443")
    ports = []
    for p in ports_raw.replace(" ", "").split(","):
        if not p:
            continue
        try:
            ports.append(int(p))
        except ValueError:
            pass
    if not ports:
        raise SystemExit("No valid PORTS")

    sample_ips = int(read_env("SAMPLE_IPS", "600"))
    output_limit = int(read_env("OUTPUT_LIMIT", "80"))
    concurrency = int(read_env("CONCURRENCY", "250"))
    timeout_sec = float(read_env("TIMEOUT_SEC", "2.5"))

    cidrs = fetch_lines("https://www.cloudflare.com/ips-v4")
    if not cidrs:
        raise SystemExit("Failed to fetch Cloudflare IPv4 ranges")

    candidates: list[tuple[str, int]] = []
    for _ in range(sample_ips):
        cidr = random.choice(cidrs)
        ip = pick_random_ipv4_from_cidr(cidr)
        port = random.choice(ports)
        candidates.append((ip, port))

    sem = asyncio.Semaphore(concurrency)

    async def one(ip: str, port: int):
        async with sem:
            ms = await probe_tls(ip, port, target_host, timeout_sec)
            return (ip, port, ms)

    results = await asyncio.gather(*(one(ip, port) for ip, port in candidates))

    ok = [(ip, port, ms) for ip, port, ms in results if ms is not None]
    ok.sort(key=lambda x: x[2])

    top = ok[:output_limit]
    lines = [f"{ip}:{port}#{int(ms)}ms" for ip, port, ms in top]
    content = "\n".join(lines).strip() + ("\n" if lines else "")

    Path("ip.txt").write_text(content, encoding="utf-8")


if __name__ == "__main__":
    asyncio.run(run())
