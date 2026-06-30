from models import db, User, LoginLog, ActivityLog, SecurityEvent, Alert, AlertSeverity, AlertStatus
from datetime import datetime, timedelta
from sqlalchemy import and_, or_, func

class ThreatDetector:
    """Threat detection engine for analyzing security events"""
    
    # Configuration
    BRUTE_FORCE_THRESHOLD = 5  # Failed attempts
    BRUTE_FORCE_WINDOW = 15  # Minutes
    SUSPICIOUS_LOGIN_WINDOW = 60  # Minutes
    SUSPICIOUS_LOCATIONS_COUNT = 3  # Different locations
    UNUSUAL_TIME_THRESHOLD = 22  # 10 PM
    
    @staticmethod
    def detect_brute_force():
        """Detect brute force login attempts"""
        window_start = datetime.utcnow() - timedelta(minutes=ThreatDetector.BRUTE_FORCE_WINDOW)
        
        # Find failed login attempts in the window
        failed_attempts = db.session.query(
            LoginLog.username,
            LoginLog.ip_address,
            func.count(LoginLog.id).label('attempt_count')
        ).filter(
            and_(
                LoginLog.success == False,
                LoginLog.timestamp >= window_start
            )
        ).group_by(
            LoginLog.username,
            LoginLog.ip_address
        ).having(
            func.count(LoginLog.id) >= ThreatDetector.BRUTE_FORCE_THRESHOLD
        ).all()
        
        for attempt in failed_attempts:
            username, ip_address, count = attempt
            
            # Check if event already exists in this window
            existing_event = SecurityEvent.query.filter(
                and_(
                    SecurityEvent.event_type == 'brute_force_attempt',
                    SecurityEvent.source_ip == ip_address,
                    SecurityEvent.detected_at >= window_start
                )
            ).first()
            
            if not existing_event:
                user = User.query.filter_by(username=username).first()
                event = SecurityEvent(
                    event_type='brute_force_attempt',
                    severity=AlertSeverity.CRITICAL,
                    description=f'Detected {count} failed login attempts for user {username} from IP {ip_address}',
                    source_user_id=user.id if user else None,
                    source_ip=ip_address,
                    affected_resource=f'user:{username}',
                    raw_data={
                        'failed_attempts': count,
                        'username': username,
                        'ip_address': ip_address
                    }
                )
                db.session.add(event)
                
                alert = Alert(
                    event=event,
                    title=f'Brute Force Attack Detected: {username}',
                    message=f'{count} failed login attempts from IP {ip_address} targeting user {username}',
                    severity=AlertSeverity.CRITICAL
                )
                db.session.add(alert)
        
        db.session.commit()
    
    @staticmethod
    def detect_unusual_locations():
        """Detect login from unusual locations"""
        # Get all users with logins in the last 24 hours
        day_ago = datetime.utcnow() - timedelta(days=1)
        
        user_locations = db.session.query(
            LoginLog.user_id,
            LoginLog.ip_address,
            LoginLog.timestamp,
            func.count(LoginLog.id).label('count')
        ).filter(
            and_(
                LoginLog.success == True,
                LoginLog.timestamp >= day_ago
            )
        ).group_by(
            LoginLog.user_id,
            LoginLog.ip_address
        ).all()
        
        # Find users with logins from multiple locations
        user_ip_counts = {}
        for login in user_locations:
            user_id, ip, timestamp, count = login
            if user_id not in user_ip_counts:
                user_ip_counts[user_id] = []
            user_ip_counts[user_id].append({'ip': ip, 'timestamp': timestamp})
        
        for user_id, locations in user_ip_counts.items():
            if len(locations) >= ThreatDetector.SUSPICIOUS_LOCATIONS_COUNT:
                user = User.query.get(user_id)
                ips = [loc['ip'] for loc in locations]
                
                event = SecurityEvent(
                    event_type='unusual_location',
                    severity=AlertSeverity.MEDIUM,
                    description=f'User {user.username} logged in from {len(ips)} different locations in 24 hours',
                    source_user_id=user_id,
                    affected_resource=f'user:{user.username}',
                    raw_data={'ips': ips}
                )
                db.session.add(event)
                
                alert = Alert(
                    event=event,
                    title=f'Unusual Login Pattern: {user.username}',
                    message=f'User logged in from {len(ips)} different IP addresses in the last 24 hours',
                    severity=AlertSeverity.MEDIUM
                )
                db.session.add(alert)
        
        db.session.commit()
    
    @staticmethod
    def detect_unusual_time_access():
        """Detect login attempts at unusual times (e.g., late night)"""
        late_night_start = datetime.utcnow() - timedelta(hours=6)
        
        late_logins = LoginLog.query.filter(
            and_(
                LoginLog.timestamp >= late_night_start,
                LoginLog.success == True
            )
        ).all()
        
        for login in late_logins:
            hour = login.timestamp.hour
            if hour >= ThreatDetector.UNUSUAL_TIME_THRESHOLD or hour < 6:
                user = User.query.get(login.user_id)
                
                # Check if we already have an event for this
                existing = SecurityEvent.query.filter(
                    and_(
                        SecurityEvent.event_type == 'unusual_time_access',
                        SecurityEvent.source_user_id == login.user_id,
                        SecurityEvent.detected_at >= late_night_start
                    )
                ).first()
                
                if not existing:
                    event = SecurityEvent(
                        event_type='unusual_time_access',
                        severity=AlertSeverity.LOW,
                        description=f'User {user.username} logged in at unusual time: {login.timestamp.strftime("%H:%M")}',
                        source_user_id=login.user_id,
                        source_ip=login.ip_address,
                        affected_resource=f'user:{user.username}',
                        raw_data={'time': login.timestamp.isoformat()}
                    )
                    db.session.add(event)
                    
                    alert = Alert(
                        event=event,
                        title=f'Unusual Login Time: {user.username}',
                        message=f'User logged in at {login.timestamp.strftime("%H:%M")} - outside normal hours',
                        severity=AlertSeverity.LOW
                    )
                    db.session.add(alert)
        
        db.session.commit()
    
    @staticmethod
    def detect_privilege_escalation():
        """Detect potential privilege escalation attempts"""
        # Find users requesting admin actions without admin role
        restricted_actions = [
            'create_user', 'delete_user', 'modify_permissions',
            'access_audit_logs', 'modify_system_config'
        ]
        
        hour_ago = datetime.utcnow() - timedelta(hours=1)
        
        suspicious_activities = ActivityLog.query.filter(
            and_(
                ActivityLog.status == 'failure',
                ActivityLog.action.in_(restricted_actions),
                ActivityLog.timestamp >= hour_ago
            )
        ).all()
        
        for activity in suspicious_activities:
            user = User.query.get(activity.user_id)
            
            if user.role.value != 'admin':
                event = SecurityEvent(
                    event_type='privilege_escalation_attempt',
                    severity=AlertSeverity.HIGH,
                    description=f'User {user.username} attempted restricted action: {activity.action}',
                    source_user_id=activity.user_id,
                    source_ip=activity.ip_address,
                    affected_resource=activity.resource,
                    raw_data={'action': activity.action, 'status': activity.status}
                )
                db.session.add(event)
                
                alert = Alert(
                    event=event,
                    title=f'Privilege Escalation Attempt: {user.username}',
                    message=f'Non-admin user attempted to perform admin action: {activity.action}',
                    severity=AlertSeverity.HIGH
                )
                db.session.add(alert)
        
        db.session.commit()
    
    @staticmethod
    def detect_bulk_data_access():
        """Detect unusual data access patterns"""
        hour_ago = datetime.utcnow() - timedelta(hours=1)
        
        user_access_counts = db.session.query(
            ActivityLog.user_id,
            func.count(ActivityLog.id).label('access_count')
        ).filter(
            and_(
                ActivityLog.action.in_(['view_report', 'export_data', 'access_resource']),
                ActivityLog.timestamp >= hour_ago
            )
        ).group_by(
            ActivityLog.user_id
        ).having(
            func.count(ActivityLog.id) > 50  # Threshold: 50 accesses in an hour
        ).all()
        
        for user_id, count in user_access_counts:
            user = User.query.get(user_id)
            
            event = SecurityEvent(
                event_type='bulk_data_access',
                severity=AlertSeverity.MEDIUM,
                description=f'User {user.username} accessed {count} resources in 1 hour',
                source_user_id=user_id,
                affected_resource='system_data',
                raw_data={'access_count': count, 'time_window': '1_hour'}
            )
            db.session.add(event)
            
            alert = Alert(
                event=event,
                title=f'Unusual Data Access: {user.username}',
                message=f'User accessed {count} resources in 1 hour - potential data exfiltration',
                severity=AlertSeverity.MEDIUM
            )
            db.session.add(alert)
        
        db.session.commit()
    
    @staticmethod
    def run_all_detectors():
        """Run all threat detection algorithms"""
        try:
            ThreatDetector.detect_brute_force()
            ThreatDetector.detect_unusual_locations()
            ThreatDetector.detect_unusual_time_access()
            ThreatDetector.detect_privilege_escalation()
            ThreatDetector.detect_bulk_data_access()
            return True
        except Exception as e:
            print(f"Error in threat detection: {str(e)}")
            return False

def log_activity(user_id, action, resource=None, resource_type=None, details=None, ip_address=None, status='success'):
    """Helper function to log user activities"""
    activity = ActivityLog(
        user_id=user_id,
        action=action,
        resource=resource,
        resource_type=resource_type,
        details=details,
        ip_address=ip_address,
        status=status
    )
    db.session.add(activity)
    db.session.commit()
    return activity
