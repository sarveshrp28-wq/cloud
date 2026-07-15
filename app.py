from flask import Flask, render_template, jsonify, request, redirect, url_for, send_from_directory
from flask_login import LoginManager, login_required, current_user
from models import (
    db,
    User,
    UserRole,
    LoginLog,
    ActivityLog,
    SecurityEvent,
    Alert,
    AlertSeverity,
    AlertStatus,
    SystemConfig
)
from auth import auth_bp, analyst_required, admin_required
from threats import ThreatDetector, log_activity
from datetime import datetime, timedelta
from sqlalchemy import func, and_
import os
from dotenv import load_dotenv

load_dotenv()

def create_app(config_name='development'):
    """Application factory"""
    app = Flask(__name__)
    
    # Configuration
    if config_name == 'production':
        app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
            'DATABASE_URL',
            'mysql+mysqlconnector://user:password@localhost/cloud_security'
        )
    else:
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cloud_security.db'
    
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    app.config['SESSION_COOKIE_SECURE'] = config_name == 'production'
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['REMEMBER_COOKIE_HTTPONLY'] = True
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
    
    # Initialize extensions
    db.init_app(app)
    
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page'
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    # Register blueprints
    app.register_blueprint(auth_bp)
    
    # Context processor
    @app.context_processor
    def inject_now():
        return {'now': datetime.utcnow}
    
    # Create database tables and seed default users
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin_user = User(
                username='admin',
                email='admin@example.com',
                role=UserRole.ADMIN
            )
            admin_user.set_password('password123')
            db.session.add(admin_user)

        if not User.query.filter_by(username='analyst').first():
            analyst_user = User(
                username='analyst',
                email='analyst@example.com',
                role=UserRole.ANALYST
            )
            analyst_user.set_password('password123')
            db.session.add(analyst_user)

        if not User.query.filter_by(username='viewer').first():
            viewer_user = User(
                username='viewer',
                email='viewer@example.com',
                role=UserRole.VIEWER
            )
            viewer_user.set_password('password123')
            db.session.add(viewer_user)

        db.session.commit()
    
    # ==================== MAIN ROUTES ====================
    
    @app.route('/')
    def index():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        return redirect(url_for('auth.login'))

    @app.route('/website-template')
    def website_template_preview():
        return send_from_directory(app.root_path, 'website_template.html')

    @app.route('/website_template.css')
    def website_template_css():
        return send_from_directory(app.root_path, 'website_template.css')
    
    @app.route('/dashboard')
    @login_required
    def dashboard():
        """Main dashboard"""
        # Get statistics
        total_alerts = Alert.query.count()
        critical_alerts = Alert.query.filter(Alert.severity == AlertSeverity.CRITICAL).count()
        open_alerts = Alert.query.filter(Alert.status == AlertStatus.OPEN).count()
        
        # Get recent events
        recent_events = SecurityEvent.query.order_by(
            SecurityEvent.detected_at.desc()
        ).limit(10).all()
        
        # Get recent logins
        recent_logins = LoginLog.query.filter(
            LoginLog.success == True
        ).order_by(LoginLog.timestamp.desc()).limit(5).all()
        
        # Get alert trends (last 7 days)
        seven_days_ago = datetime.utcnow() - timedelta(days=7)
        alert_counts = db.session.query(
            func.date(Alert.created_at).label('date'),
            func.count(Alert.id).label('count')
        ).filter(
            Alert.created_at >= seven_days_ago
        ).group_by(
            func.date(Alert.created_at)
        ).all()
        
        chart_data = {
            'dates': [str(item[0]) for item in alert_counts],
            'counts': [item[1] for item in alert_counts]
        }
        
        return render_template('dashboard.html',
                             total_alerts=total_alerts,
                             critical_alerts=critical_alerts,
                             open_alerts=open_alerts,
                             recent_events=recent_events,
                             recent_logins=recent_logins,
                             chart_data=chart_data)
    
    # ==================== ALERTS ROUTES ====================
    
    @app.route('/alerts')
    @login_required
    @analyst_required
    def alerts_list():
        """List all alerts"""
        status = request.args.get('status')
        severity = request.args.get('severity')
        page = request.args.get('page', 1, type=int)
        
        query = Alert.query
        
        if status:
            try:
                status_enum = AlertStatus(status)
                query = query.filter(Alert.status == status_enum)
            except ValueError:
                pass
        
        if severity:
            try:
                severity_enum = AlertSeverity(severity)
                query = query.filter(Alert.severity == severity_enum)
            except ValueError:
                pass
        
        alerts = query.order_by(Alert.created_at.desc()).paginate(page=page, per_page=20)
        
        return render_template('alerts/list.html', alerts=alerts)
    
    @app.route('/alerts/<int:alert_id>')
    @login_required
    @analyst_required
    def alert_detail(alert_id):
        """View alert details"""
        alert = Alert.query.get_or_404(alert_id)
        event = alert.event
        
        # Log activity
        log_activity(
            current_user.id,
            'view_alert',
            resource=f'alert:{alert_id}',
            resource_type='alert',
            ip_address=request.remote_addr
        )
        
        return render_template('alerts/detail.html', alert=alert, event=event)
    
    @app.route('/alerts/<int:alert_id>/acknowledge', methods=['POST'])
    @login_required
    @analyst_required
    def acknowledge_alert(alert_id):
        """Acknowledge an alert"""
        alert = Alert.query.get_or_404(alert_id)
        alert.status = AlertStatus.ACKNOWLEDGED
        alert.acknowledged_at = datetime.utcnow()
        alert.assigned_to = current_user.id
        db.session.commit()
        
        log_activity(
            current_user.id,
            'acknowledge_alert',
            resource=f'alert:{alert_id}',
            resource_type='alert',
            ip_address=request.remote_addr
        )
        
        return jsonify({'status': 'success', 'message': 'Alert acknowledged'})
    
    @app.route('/alerts/<int:alert_id>/resolve', methods=['POST'])
    @login_required
    @analyst_required
    def resolve_alert(alert_id):
        """Resolve an alert"""
        alert = Alert.query.get_or_404(alert_id)
        resolution_notes = request.form.get('resolution_notes', '')
        
        alert.status = AlertStatus.RESOLVED
        alert.resolved_at = datetime.utcnow()
        alert.resolution_notes = resolution_notes
        db.session.commit()
        
        log_activity(
            current_user.id,
            'resolve_alert',
            resource=f'alert:{alert_id}',
            resource_type='alert',
            details=resolution_notes,
            ip_address=request.remote_addr
        )
        
        return jsonify({'status': 'success', 'message': 'Alert resolved'})
    
    # ==================== EVENTS ROUTES ====================
    
    @app.route('/events')
    @login_required
    @analyst_required
    def events_list():
        """List security events"""
        event_type = request.args.get('type')
        severity = request.args.get('severity')
        page = request.args.get('page', 1, type=int)
        
        query = SecurityEvent.query
        
        if event_type:
            query = query.filter(SecurityEvent.event_type == event_type)
        
        if severity:
            try:
                severity_enum = AlertSeverity(severity)
                query = query.filter(SecurityEvent.severity == severity_enum)
            except ValueError:
                pass
        
        events = query.order_by(SecurityEvent.detected_at.desc()).paginate(page=page, per_page=20)
        
        return render_template('events/list.html', events=events)
    
    @app.route('/events/<int:event_id>')
    @login_required
    @analyst_required
    def event_detail(event_id):
        """View event details"""
        event = SecurityEvent.query.get_or_404(event_id)
        related_alerts = event.alerts
        
        log_activity(
            current_user.id,
            'view_event',
            resource=f'event:{event_id}',
            resource_type='event',
            ip_address=request.remote_addr
        )
        
        return render_template('events/detail.html', event=event, alerts=related_alerts)
    
    # ==================== REPORTS ROUTES ====================
    
    @app.route('/reports')
    @login_required
    @analyst_required
    def reports():
        """Reports dashboard"""
        # Security summary
        today = datetime.utcnow().date()
        week_ago = datetime.utcnow() - timedelta(days=7)
        
        today_events = SecurityEvent.query.filter(
            func.date(SecurityEvent.detected_at) == today
        ).count()
        
        week_events = SecurityEvent.query.filter(
            SecurityEvent.detected_at >= week_ago
        ).count()
        
        # Event type distribution
        event_dist_query = db.session.query(
            SecurityEvent.event_type,
            func.count(SecurityEvent.id).label('count')
        ).filter(
            SecurityEvent.detected_at >= week_ago
        ).group_by(SecurityEvent.event_type).all()
        event_distribution = [
            {'type': event_type, 'count': count} for event_type, count in event_dist_query
        ]
        
        # Severity distribution for reports
        severity_distribution_query = db.session.query(
            SecurityEvent.severity,
            func.count(SecurityEvent.id).label('count')
        ).filter(
            SecurityEvent.detected_at >= week_ago
        ).group_by(SecurityEvent.severity).all()
        severity_distribution = [
            (severity.value, count) for severity, count in severity_distribution_query
        ]
        severity_labels = [
            severity.replace('_', ' ').title() for severity, count in severity_distribution
        ]
        severity_counts = [count for severity, count in severity_distribution]
        
        # Alert resolution stats
        resolved_alerts = Alert.query.filter(
            Alert.status == AlertStatus.RESOLVED
        ).count()
        
        total_alerts = Alert.query.count()
        resolution_rate = (resolved_alerts / total_alerts * 100) if total_alerts > 0 else 0
        
        return render_template('reports.html',
                             today_events=today_events,
                             week_events=week_events,
                             event_distribution=event_distribution,
                             severity_distribution=severity_distribution,
                             severity_labels=severity_labels,
                             severity_counts=severity_counts,
                             resolved_alerts=resolved_alerts,
                             resolution_rate=resolution_rate)
    
    # ==================== ADMIN ROUTES ====================
    
    @app.route('/admin/users')
    @login_required
    @admin_required
    def manage_users():
        """User management"""
        users = User.query.all()
        role_counts = {
            'admin': sum(1 for user in users if user.role == UserRole.ADMIN),
            'analyst': sum(1 for user in users if user.role == UserRole.ANALYST),
            'viewer': sum(1 for user in users if user.role == UserRole.VIEWER)
        }
        users_json = [
            {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role': user.role.value,
                'is_active': user.is_active,
                'created_at': user.created_at.isoformat() if user.created_at else None
            }
            for user in users
        ]
        return render_template(
            'admin/users.html',
            users=users,
            users_json=users_json,
            role_counts=role_counts,
            active_count=sum(1 for user in users if user.is_active)
        )
    
    @app.route('/admin/users/<int:user_id>/toggle-active', methods=['POST'])
    @login_required
    @admin_required
    def toggle_user_active(user_id):
        """Toggle user active status"""
        user = User.query.get_or_404(user_id)
        user.is_active = not user.is_active
        db.session.commit()
        
        log_activity(
            current_user.id,
            'toggle_user_status',
            resource=f'user:{user.username}',
            resource_type='user',
            details=f'Active: {user.is_active}',
            ip_address=request.remote_addr
        )
        
        return jsonify({'status': 'success', 'is_active': user.is_active})
    
    @app.route('/admin/logs')
    @login_required
    @admin_required
    def audit_logs():
        """View audit logs"""
        page = request.args.get('page', 1, type=int)
        logs = ActivityLog.query.order_by(
            ActivityLog.timestamp.desc()
        ).paginate(page=page, per_page=50)
        
        return render_template('admin/logs.html', logs=logs)
    
    # ==================== API ROUTES ====================
    
    @app.route('/api/alerts/summary')
    @login_required
    def api_alerts_summary():
        """API endpoint for alert summary"""
        total = Alert.query.count()
        critical = Alert.query.filter(Alert.severity == AlertSeverity.CRITICAL).count()
        open_count = Alert.query.filter(Alert.status == AlertStatus.OPEN).count()
        
        return jsonify({
            'total': total,
            'critical': critical,
            'open': open_count,
            'resolution_rate': calculate_resolution_rate()
        })
    
    @app.route('/api/events/recent')
    @login_required
    @analyst_required
    def api_recent_events():
        """API endpoint for recent events"""
        limit = request.args.get('limit', 10, type=int)
        events = SecurityEvent.query.order_by(
            SecurityEvent.detected_at.desc()
        ).limit(limit).all()
        
        return jsonify({
            'events': [event.to_dict() for event in events]
        })
    
    @app.route('/api/run-threat-detection', methods=['POST'])
    @login_required
    @admin_required
    def run_threat_detection():
        """Manually trigger threat detection"""
        success = ThreatDetector.run_all_detectors()
        
        log_activity(
            current_user.id,
            'run_threat_detection',
            resource='system',
            resource_type='system',
            ip_address=request.remote_addr
        )
        
        return jsonify({
            'status': 'success' if success else 'error',
            'message': 'Threat detection completed' if success else 'Error running threat detection'
        })
    
    # ==================== ERROR HANDLERS ====================
    
    @app.errorhandler(404)
    def not_found(e):
        return render_template('errors/404.html'), 404
    
    @app.errorhandler(403)
    def forbidden(e):
        return render_template('errors/403.html'), 403
    
    @app.errorhandler(500)
    def internal_error(e):
        db.session.rollback()
        return render_template('errors/500.html'), 500
    
    # ==================== HELPER FUNCTIONS ====================
    
    def calculate_resolution_rate():
        """Calculate alert resolution rate"""
        total = Alert.query.count()
        if total == 0:
            return 0
        resolved = Alert.query.filter(Alert.status == AlertStatus.RESOLVED).count()
        return (resolved / total) * 100
    
    return app

if __name__ == '__main__':
    app = create_app('development')
    app.run(debug=True, host='0.0.0.0', port=5000)
