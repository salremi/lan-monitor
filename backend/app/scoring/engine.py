"""Scoring engine: runs all rules per device, writes alerts."""
import logging
from datetime import datetime, timedelta
from sqlalchemy.orm import Session, selectinload

from app.models.device import Device
from app.models.event import NetworkEvent
from app.models.alert import Alert, AlertSeverity
from app.scoring.rules import ALL_RULES, RuleResult

logger = logging.getLogger(__name__)


def _load_config(db: Session) -> dict:
    from app.models.app_config import AppConfig
    entries = db.query(AppConfig).all()
    return {e.key: e.value for e in entries}


def _score_to_severity(score: float) -> AlertSeverity:
    if score >= 75:
        return AlertSeverity.critical
    if score >= 50:
        return AlertSeverity.high
    if score >= 25:
        return AlertSeverity.medium
    return AlertSeverity.low


def _run_device(device: Device, events: list[NetworkEvent], config: dict) -> tuple[float, list[dict], list[int]]:
    """Run all rules for one device. Returns (total_delta, reasons, all_evidence_ids)."""
    reasons = []
    all_evidence_ids = []
    total_delta = 0.0

    for rule_fn in ALL_RULES:
        try:
            result: RuleResult = rule_fn(device, events, config)
            if result.score_delta > 0:
                reasons.append({
                    "rule": rule_fn.__name__,
                    "delta": result.score_delta,
                    "explanation": result.explanation,
                })
                total_delta += result.score_delta
                all_evidence_ids.extend(result.evidence_ids)
        except Exception:
            logger.exception("Rule %s failed for device %s", rule_fn.__name__, device.ip)

    # Clamp total
    total_delta = max(0.0, min(100.0, total_delta))
    return total_delta, reasons, list(set(all_evidence_ids))


def run_scoring_engine(db: Session) -> None:
    """Score all non-suppressed devices and generate alerts on significant changes."""
    config = _load_config(db)
    alert_threshold = float(config.get("alert_score_change_threshold", 10.0))
    lookback = datetime.utcnow() - timedelta(hours=24)

    devices = (
        db.query(Device)
        .filter(Device.suppressed == False)  # noqa: E712
        .options(
            selectinload(Device.ports),
            selectinload(Device.baselines),
        )
        .all()
    )

    for device in devices:
        events = (
            db.query(NetworkEvent)
            .filter(
                NetworkEvent.device_id == device.id,
                NetworkEvent.ts >= lookback,
            )
            .all()
        )

        prev_score = device.suspicion_score or 0.0
        new_score, reasons, evidence_ids = _run_device(device, events, config)

        device.suspicion_score = new_score
        device.score_reasons = reasons

        score_change = abs(new_score - prev_score)
        if score_change >= alert_threshold and new_score > 0:
            severity = _score_to_severity(new_score)
            # Build evidence summaries
            evidence_summaries = []
            if evidence_ids:
                ev_events = (
                    db.query(NetworkEvent)
                    .filter(NetworkEvent.id.in_(evidence_ids[:50]))
                    .all()
                )
                for ev in ev_events:
                    evidence_summaries.append({
                        "event_id": ev.id,
                        "type": ev.event_type,
                        "src": ev.source_ip,
                        "dst": ev.dest_ip,
                        "ts": ev.ts.isoformat(),
                    })

            reason_text = "; ".join(r["explanation"] for r in reasons if r.get("explanation"))
            alert = Alert(
                device_id=device.id,
                severity=severity,
                title=f"Suspicion score changed: {prev_score:.1f} → {new_score:.1f}",
                reason=reason_text or "Score increased",
                evidence=evidence_summaries,
                created_at=datetime.utcnow(),
                acknowledged=False,
            )
            db.add(alert)
            logger.info(
                "Alert created for device %s: score %.1f → %.1f (%s)",
                device.ip, prev_score, new_score, severity.value,
            )

    db.commit()
    logger.info("Scoring engine completed for %d devices", len(devices))
