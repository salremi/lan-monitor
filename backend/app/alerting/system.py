"""Alerting system for network security monitoring."""
import logging
from typing import Dict, Any
from datetime import datetime

logger = logging.getLogger(__name__)

class AlertSystem:
    """System for generating and managing security alerts."""
    
    def __init__(self):
        self.alerts = []
        
    def create_alert(self, alert_type: str, severity: str, message: str, 
                     source_ip: str = None, details: Dict[str, Any] = None) -> Dict[str, Any]:
        """Create a new security alert."""
        alert = {
            "id": len(self.alerts) + 1,
            "type": alert_type,
            "severity": severity,
            "message": message,
            "source_ip": source_ip,
            "timestamp": datetime.now(),
            "details": details or {}
        }
        
        self.alerts.append(alert)
        return alert
        
    def send_notification(self, alert: Dict[str, Any]) -> None:
        """Send notification for a security alert."""
        logger.info(f"Security alert: {alert['message']}")
        # In a real implementation, this would send an actual notification
        
    def check_proxy_alerts(self, device_data: Dict[str, Any]) -> None:
        """Check for proxy-related alerts."""
        # Check for exposed proxy ports
        if device_data.get('port') in [8080, 3128, 1080, 8888]:
            alert = self.create_alert(
                "proxy_detected",
                "high",
                f"Proxy service detected on port {device_data.get('port')}",
                device_data.get('ip'),
                {"port": device_data.get('port'), "confidence": device_data.get('confidence', 0.0)}
            )
            self.send_notification(alert)
            
    def check_anomaly_alerts(self, traffic_data: Dict[str, Any]) -> None:
        """Check for anomaly alerts."""
        # Check for unusual traffic patterns
        if traffic_data.get('anomaly_score', 0) > 50:
            alert = self.create_alert(
                "high_anomaly",
                "high",
                "Unusual network traffic detected",
                traffic_data.get('source_ip'),
                {"anomaly_score": traffic_data.get('anomaly_score', 0)}
            )
            self.send_notification(alert)
