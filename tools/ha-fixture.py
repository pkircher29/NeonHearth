#!/usr/bin/env python3
"""Local protocol fixture for browser acceptance; all devices are simulated."""
import asyncio
from datetime import datetime, timezone
import json
from websockets.asyncio.server import serve

TOKEN = "local-fixture-token-never-use-for-real-ha"
ENTITIES = [("light.demo_lounge", "Demo lounge lamp", "lounge", "light"),
            ("switch.demo_office", "Demo office outlet", "office", "switch"),
            ("sensor.demo_kitchen", "Demo kitchen temperature", "kitchen", "sensor")]


async def connection(ws):
    await ws.send(json.dumps({"type": "auth_required"}))
    auth = json.loads(await ws.recv())
    if auth.get("access_token") != TOKEN:
        await ws.send(json.dumps({"type": "auth_invalid"}))
        return
    await ws.send(json.dumps({"type": "auth_ok"}))
    now = datetime.now(timezone.utc).isoformat()
    states = {entity: {"entity_id": entity, "state": "21.5" if domain == "sensor" else "off",
                      "last_changed": now, "last_updated": now,
                      "attributes": {"friendly_name": name}} for entity, name, _, domain in ENTITIES}
    subscription = 0
    async for data in ws:
        message = json.loads(data)
        kind, msg_id = message["type"], message["id"]
        if kind == "subscribe_events":
            subscription, result = msg_id, None
        elif kind == "config/area_registry/list":
            result = [{"area_id": area, "name": area.title()} for area in ("lounge", "office", "kitchen")]
        elif kind == "config/device_registry/list":
            result = [{"id": entity, "name": name, "manufacturer": "Simulated device", "model": "QA fixture",
                       "area_id": area, "connections": []} for entity, name, area, _ in ENTITIES]
        elif kind == "config/entity_registry/list":
            result = [{"entity_id": entity, "device_id": entity, "platform": "mqtt", "area_id": area} for entity, _, area, _ in ENTITIES]
        elif kind == "get_states":
            result = list(states.values())
        elif kind == "get_services":
            result = {domain: {"turn_on": {}, "turn_off": {}} for domain in ("light", "switch")}
        elif kind == "call_service":
            entity = message["target"]["entity_id"]
            states[entity]["state"] = "on" if message["service"] == "turn_on" else "off"
            states[entity]["last_changed"] = states[entity]["last_updated"] = datetime.now(timezone.utc).isoformat()
            await ws.send(json.dumps({"id": subscription, "type": "event", "event": {"data": {"entity_id": entity, "new_state": states[entity]}}}))
            result = {"context": {"id": "fixture"}}
        elif kind == "ping":
            await ws.send(json.dumps({"id": msg_id, "type": "pong"}))
            continue
        else:
            await ws.send(json.dumps({"id": msg_id, "type": "result", "success": False, "error": {"code": "unsupported"}}))
            continue
        await ws.send(json.dumps({"id": msg_id, "type": "result", "success": True, "result": result}))


async def main():
    async with serve(connection, "127.0.0.1", 58124, max_size=65536):
        print("Simulated Home Assistant fixture at http://127.0.0.1:58124", flush=True)
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
