"""Redis Stream Consumer Group worker on events:raw."""

from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sentinel_common.detection.pipeline import DetectionResult, ThreatDetectionPipeline
from sentinel_common.logger import logger


class EventDetectionConsumer:
    """Consumes normalized events from Redis Stream 'events:raw' using Consumer Groups.

    Orchestrates:
    - Consumer Group initialization ('events:raw' -> 'detection_workers')
    - Reading batches with XREADGROUP
    - Evaluating each event across Sigma, Threshold, IOC, and ML layers
    - Saving alerts and publishing to Redis Stream 'alerts:new'
    - Acknowledging messages with XACK
    """

    def __init__(
        self,
        redis_client: Any,
        session_factory: async_sessionmaker[AsyncSession] | None = None,
        pipeline: ThreatDetectionPipeline | None = None,
        stream_name: str = "events:raw",
        group_name: str = "detection_workers",
        consumer_name: str | None = None,
    ) -> None:
        self.redis = redis_client
        self.session_factory = session_factory
        self.pipeline = pipeline or ThreatDetectionPipeline()
        self.stream_name = stream_name
        self.group_name = group_name
        self.consumer_name = consumer_name or f"worker-{uuid.uuid4().hex[:6]}"
        self.is_running = False

    async def init_consumer_group(self) -> None:
        """Create stream and consumer group if they don't already exist."""
        try:
            await self.redis.xgroup_create(
                name=self.stream_name,
                groupname=self.group_name,
                id="$",
                mkstream=True,
            )
            logger.info(f"Created Redis consumer group '{self.group_name}' on stream '{self.stream_name}'")
        except Exception as e:
            # BUSYGROUP error occurs when group already exists, which is expected
            if "BUSYGROUP" in str(e):
                logger.debug(f"Consumer group '{self.group_name}' already exists.")
            else:
                logger.warning(f"Error checking consumer group: {e}")

    async def process_message(
        self,
        message_id: str,
        message_data: dict[Any, Any],
        db_session: AsyncSession | None = None,
    ) -> DetectionResult | None:
        """Process a single event message from Redis stream."""
        # Normalize message payload
        raw_event: dict[str, Any] = {}
        if "payload" in message_data:
            val = message_data["payload"]
            if isinstance(val, (bytes, str)):
                try:
                    raw_event = json.loads(val)
                except Exception:
                    raw_event = {"raw_payload": str(val)}
            elif isinstance(val, dict):
                raw_event = val
        else:
            # Decode string keys if bytes
            raw_event = {
                (k.decode() if isinstance(k, bytes) else str(k)): (v.decode() if isinstance(v, bytes) else v)
                for k, v in message_data.items()
            }

        tenant_id = str(raw_event.get("tenant_id") or "default")

        result = await self.pipeline.analyze_event(
            event=raw_event,
            redis_client=self.redis,
            db_session=db_session,
            tenant_id=tenant_id,
            publish_alert=True,
        )

        # Acknowledge the message
        try:
            await self.redis.xack(self.stream_name, self.group_name, message_id)
        except Exception as ack_err:
            logger.error(f"Failed to ACK message {message_id}: {ack_err}")

        return result

    async def process_batch(self, count: int = 10, block_ms: int = 1000) -> list[DetectionResult]:
        """Read and process a batch of events using XREADGROUP."""
        results: list[DetectionResult] = []
        try:
            entries = await self.redis.xreadgroup(
                groupname=self.group_name,
                consumername=self.consumer_name,
                streams={self.stream_name: ">"},
                count=count,
                block=block_ms,
            )
        except Exception as e:
            logger.error(f"Error reading from stream {self.stream_name}: {e}")
            return results

        if not entries:
            return results

        for _stream_name, messages in entries:
            for message_id, message_data in messages:
                m_id = message_id.decode() if isinstance(message_id, bytes) else str(message_id)

                if self.session_factory:
                    async with self.session_factory() as session:
                        res = await self.process_message(m_id, message_data, db_session=session)
                        await session.commit()
                else:
                    res = await self.process_message(m_id, message_data, db_session=None)

                if res:
                    results.append(res)

        return results

    async def run_forever(self, poll_interval: float = 0.1) -> None:
        """Main event loop consuming messages until cancelled."""
        self.is_running = True
        await self.init_consumer_group()
        logger.info(f"Detection consumer {self.consumer_name} running on {self.stream_name}...")

        while self.is_running:
            try:
                await self.process_batch(count=50, block_ms=2000)
                await asyncio.sleep(poll_interval)
            except asyncio.CancelledError:
                self.is_running = False
                break
            except Exception as e:
                logger.error(f"Unexpected error in detection consumer loop: {e}")
                await asyncio.sleep(1)

    def stop(self) -> None:
        """Stop consumer loop."""
        self.is_running = False
