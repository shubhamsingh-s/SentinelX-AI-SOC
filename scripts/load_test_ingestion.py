"""High-performance load test script benchmarking SentinelX Ingestion Service at 5,000 events/sec."""

import argparse
import asyncio
import json
import random
import sys
import time
from datetime import UTC, datetime

import httpx

SAMPLE_SOURCE_TYPES = ["syslog", "firewall", "cloudtrail", "edr", "auth", "windows_event"]
SAMPLE_ACTIONS = ["allow", "deny", "login_failure", "login_success", "process_create", "network_connect"]
SAMPLE_SEVERITIES = ["info", "low", "medium", "high", "critical"]
SAMPLE_USERS = ["admin", "analyst", "root", "svc_app", "jdoe", "asmith", "guest"]
SAMPLE_IPS = ["192.168.1.10", "10.0.0.50", "172.16.0.4", "192.168.1.100", "10.0.0.99", "8.8.8.8"]


def generate_event_batch(batch_size: int) -> list[dict]:
    """Generate a batch of synthetic security events adhering to Common Event Schema."""
    now_iso = datetime.now(UTC).isoformat()
    events = []
    for _ in range(batch_size):
        src_ip = random.choice(SAMPLE_IPS)
        dst_ip = random.choice(SAMPLE_IPS)
        source_type = random.choice(SAMPLE_SOURCE_TYPES)
        action = random.choice(SAMPLE_ACTIONS)
        user = random.choice(SAMPLE_USERS)

        events.append(
            {
                "timestamp": now_iso,
                "source_type": source_type,
                "event_name": f"{source_type}_{action}",
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "source_port": random.randint(1024, 65535),
                "destination_port": random.choice([22, 80, 443, 3389, 8080, 53]),
                "protocol": random.choice(["TCP", "UDP", "HTTPS"]),
                "username": user,
                "hostname": f"srv-{random.randint(1, 20):02d}.internal",
                "action": action,
                "severity": random.choice(SAMPLE_SEVERITIES),
                "raw_payload": f"<134>1 {now_iso} srv-01 {source_type} 1234 - - Event {action} by user {user} from {src_ip}",
                "extra_fields": {"process_id": random.randint(100, 9999), "threat_score": random.random()},
            }
        )
    return events


async def worker(
    worker_id: int,
    client: httpx.AsyncClient,
    url: str,
    headers: dict,
    batch_size: int,
    end_time: float,
    rate_delay: float,
    latencies: list[float],
    stats: dict,
) -> None:
    """Async worker continuously sending event batches at target rate."""
    while time.time() < end_time:
        batch = generate_event_batch(batch_size)
        payload = {"events": batch}

        req_start = time.perf_counter()
        try:
            resp = await client.post(url, json=payload, headers=headers, timeout=10.0)
            latency = (time.perf_counter() - req_start) * 1000.0
            latencies.append(latency)

            if resp.status_code == 202 or resp.status_code == 200:
                stats["events_sent"] += batch_size
                stats["success_requests"] += 1
            else:
                stats["failed_requests"] += 1
        except Exception:
            stats["failed_requests"] += 1

        if rate_delay > 0:
            await asyncio.sleep(rate_delay)


async def run_load_test(
    url: str,
    api_key: str,
    target_eps: int,
    batch_size: int,
    duration: int,
    concurrency: int,
) -> None:
    """Execute load test targeting target_eps (events/second)."""
    batches_per_sec = target_eps / batch_size
    delay_per_worker = (concurrency / batches_per_sec) if batches_per_sec > 0 else 0.0

    print("=" * 70)
    print(" SentinelX Ingestion Benchmark - 5,000 Events/Sec Load Test")
    print("=" * 70)
    print(f" Target Endpoint:   {url}")
    print(f" Target Rate:       {target_eps:,} events/sec")
    print(f" Batch Size:        {batch_size} events per request")
    print(f" Required Batches:  {batches_per_sec:.1f} batches/sec")
    print(f" Concurrency:       {concurrency} async workers")
    print(f" Test Duration:     {duration} seconds")
    print("=" * 70)

    headers = {
        "Content-Type": "application/json",
        "X-API-Key": api_key,
    }

    latencies: list[float] = []
    stats = {
        "events_sent": 0,
        "success_requests": 0,
        "failed_requests": 0,
    }

    limits = httpx.Limits(max_keepalive_connections=concurrency, max_connections=concurrency * 2)
    async with httpx.AsyncClient(limits=limits) as client:
        start_time = time.time()
        end_time = start_time + duration

        workers = [
            worker(
                worker_id=i,
                client=client,
                url=url,
                headers=headers,
                batch_size=batch_size,
                end_time=end_time,
                rate_delay=delay_per_worker,
                latencies=latencies,
                stats=stats,
            )
            for i in range(concurrency)
        ]

        print(f"Starting benchmark for {duration} seconds...")
        await asyncio.gather(*workers)
        total_time = time.time() - start_time

    # Compute metrics
    total_events = stats["events_sent"]
    actual_eps = total_events / total_time if total_time > 0 else 0

    print("\n" + "=" * 70)
    print(" Benchmark Results")
    print("=" * 70)
    print(f" Elapsed Time:         {total_time:.2f} s")
    print(f" Total Events Ingested:{total_events:,}")
    print(f" Actual Throughput:    {actual_eps:,.2f} events/sec")
    print(f" Successful Batches:   {stats['success_requests']}")
    print(f" Failed Batches:       {stats['failed_requests']}")

    if latencies:
        latencies.sort()
        avg_lat = sum(latencies) / len(latencies)
        p50 = latencies[int(len(latencies) * 0.50)]
        p95 = latencies[int(len(latencies) * 0.95)]
        p99 = latencies[int(len(latencies) * 0.99)]
        print(f" Latency Mean:         {avg_lat:.2f} ms")
        print(f" Latency p50:          {p50:.2f} ms")
        print(f" Latency p95:          {p95:.2f} ms")
        print(f" Latency p99:          {p99:.2f} ms")

    if actual_eps >= target_eps * 0.9:
        print("\n[SUCCESS] Ingestion Service achieved target 5,000 events/sec capacity!")
    else:
        print(f"\n[INFO] Target throughput was {target_eps} eps, achieved {actual_eps:.1f} eps.")
    print("=" * 70)


def main() -> None:
    parser = argparse.ArgumentParser(description="SentinelX Ingestion 5,000 EPS Load Tester")
    parser.add_argument("--url", default="http://localhost:8000/api/v1/ingest/events", help="Ingestion endpoint URL")
    parser.add_argument("--api-key", default="sx_live_test_api_key", help="API Key for ingestion authentication")
    parser.add_argument("--target-rate", type=int, default=5000, help="Target events per second (default: 5000)")
    parser.add_argument("--batch-size", type=int, default=500, help="Events per request batch (max 1000, default: 500)")
    parser.add_argument("--duration", type=int, default=10, help="Benchmark run duration in seconds (default: 10)")
    parser.add_argument("--concurrency", type=int, default=15, help="Number of concurrent workers (default: 15)")

    args = parser.parse_args()
    asyncio.run(
        run_load_test(
            url=args.url,
            api_key=args.api_key,
            target_eps=args.target_rate,
            batch_size=args.batch_size,
            duration=args.duration,
            concurrency=args.concurrency,
        )
    )


if __name__ == "__main__":
    main()
