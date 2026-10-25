"""Terminal control surface for scheduled outreach state."""
from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from bridge.outreach import CampaignSpec, OutreachError, OutreachStore


def _recipients(path: str) -> list[str]:
    return [
        line.strip()
        for line in Path(path).read_text(encoding="utf-8-sig").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Telegram outreach scheduler")
    p.add_argument("--db", required=True)
    sub = p.add_subparsers(dest="cmd", required=True)

    create = sub.add_parser("create")
    create.add_argument("--campaign", required=True)
    create.add_argument("--message-file", required=True)
    create.add_argument("--recipients-file", required=True)
    create.add_argument("--daily-limit", required=True, type=int)
    create.add_argument("--interval-seconds", type=int, default=0)
    create.add_argument("--timezone", default="UTC")
    create.add_argument("--window-start", default="00:00")
    create.add_argument("--window-end", default="00:00")

    for name in ("status", "preview", "claim", "pause", "resume"):
        q = sub.add_parser(name)
        q.add_argument("--campaign", required=True)

    sent = sub.add_parser("mark-sent")
    sent.add_argument("--campaign", required=True)
    sent.add_argument("--recipient", required=True)

    failed = sub.add_parser("mark-failed")
    failed.add_argument("--campaign", required=True)
    failed.add_argument("--recipient", required=True)
    failed.add_argument("--error", required=True)
    failed.add_argument("--retry-after-seconds", type=int, default=0)
    failed.add_argument("--permanent", action="store_true")
    return p


def _print(value) -> None:
    print(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2))


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    store = OutreachStore(Path(args.db))
    try:
        if args.cmd == "create":
            spec = CampaignSpec(
                campaign_id=args.campaign,
                message_text=Path(args.message_file).read_text(encoding="utf-8-sig"),
                daily_limit=args.daily_limit,
                interval_seconds=args.interval_seconds,
                timezone_name=args.timezone,
                window_start=args.window_start,
                window_end=args.window_end,
            )
            result = store.create_campaign(spec, _recipients(args.recipients_file))
        elif args.cmd == "status":
            result = store.status(args.campaign)
        elif args.cmd == "preview":
            item = store.preview_next(args.campaign)
            result = None if item is None else asdict(item)
        elif args.cmd == "claim":
            item = store.claim_next(args.campaign)
            result = None if item is None else asdict(item)
        elif args.cmd == "pause":
            store.pause(args.campaign)
            result = store.status(args.campaign)
        elif args.cmd == "resume":
            store.resume(args.campaign)
            result = store.status(args.campaign)
        elif args.cmd == "mark-sent":
            result = store.mark_sent(args.campaign, args.recipient)
        elif args.cmd == "mark-failed":
            result = store.mark_failed(
                args.campaign,
                args.recipient,
                error=args.error,
                retry_after_seconds=args.retry_after_seconds,
                permanent=args.permanent,
            )
        else:
            raise AssertionError(args.cmd)
    except (OSError, OutreachError) as exc:
        _print({"ok": False, "error": str(exc)})
        return 2
    _print({"ok": True, "result": result})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
