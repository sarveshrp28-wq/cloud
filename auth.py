from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from models import db, User, LoginLog, UserRole, SecurityEvent, Alert, AlertSeverity
from datetime import datetime
from functools import wraps

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

def get_client_ip():
    """Get client IP address from request"""
    if request.environ.get('HTTP_X_FORWARDED_FOR'):
        return request.environ.get('HTTP_X_FORWARDED_FOR').split(',')[0]
    return request.environ.get('REMOTE_ADDR')

def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != UserRole.ADMIN:
            flash('Admin access required', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def analyst_required(f):
    """Decorator to require analyst or admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role not in [UserRole.ADMIN, UserRole.ANALYST]:
            flash('Analyst access required', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validation
        if not username or not email or not password:
            flash('All fields are required', 'danger')
            return redirect(url_for('auth.register'))
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('auth.register'))
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('auth.register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'danger')
            return redirect(url_for('auth.register'))
        
        # Create new user
        user = User(username=username, email=email, role=UserRole.VIEWER)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('auth/register.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login with failed attempt tracking"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        ip_address = get_client_ip()
        user_agent = request.headers.get('User-Agent', '')[:500]
        
        user = User.query.filter_by(username=username).first()
        
        # Check if account is locked due to failed attempts
        if user and user.failed_login_attempts >= 5:
            login_log = LoginLog(
                user_id=user.id,
                username=username,
                ip_address=ip_address,
                user_agent=user_agent,
                success=False,
                reason='Account locked - too many failed attempts'
            )
            db.session.add(login_log)
            db.session.commit()
            
            # Create security event for account lockout
            event = SecurityEvent(
                event_type='account_lockout',
                severity=AlertSeverity.HIGH,
                description=f'Account {username} locked due to multiple failed login attempts',
                source_user_id=user.id,
                source_ip=ip_address,
                affected_resource=f'user:{username}',
                raw_data={'failed_attempts': user.failed_login_attempts}
            )
            db.session.add(event)
            
            alert = Alert(
                event=event,
                title=f'Account Lockout: {username}',
                message=f'User account {username} has been locked after {user.failed_login_attempts} failed login attempts from IP {ip_address}',
                severity=AlertSeverity.HIGH
            )
            db.session.add(alert)
            db.session.commit()
            
            flash('Account locked due to multiple failed attempts. Contact administrator.', 'danger')
            return redirect(url_for('auth.login'))
        
        # Validate credentials
        if user and user.check_password(password) and user.is_active:
            user.last_login = datetime.utcnow()
            user.reset_failed_login()
            db.session.commit()
            
            # Log successful login
            login_log = LoginLog(
                user_id=user.id,
                username=username,
                ip_address=ip_address,
                user_agent=user_agent,
                success=True
            )
            db.session.add(login_log)
            db.session.commit()
            
            login_user(user, remember=request.form.get('remember_me'))
            flash(f'Welcome back, {username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            # Failed login attempt
            if user:
                user.increment_failed_login()
                failed_count = user.failed_login_attempts
                
                login_log = LoginLog(
                    user_id=user.id,
                    username=username,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    success=False,
                    reason='Invalid password'
                )
                
                # Create security event for multiple failed attempts
                if failed_count >= 3:
                    event = SecurityEvent(
                        event_type='brute_force_attempt',
                        severity=AlertSeverity.HIGH if failed_count >= 3 else AlertSeverity.MEDIUM,
                        description=f'Multiple failed login attempts for user {username}',
                        source_user_id=user.id,
                        source_ip=ip_address,
                        affected_resource=f'user:{username}',
                        raw_data={'failed_attempts': failed_count}
                    )
                    db.session.add(event)
                    
                    alert = Alert(
                        event=event,
                        title=f'Brute Force Attempt: {username}',
                        message=f'User {username} has {failed_count} failed login attempts from IP {ip_address}',
                        severity=AlertSeverity.HIGH if failed_count >= 3 else AlertSeverity.MEDIUM
                    )
                    db.session.add(alert)
            else:
                login_log = LoginLog(
                    user_id=None,
                    username=username,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    success=False,
                    reason='User not found'
                )
            
            db.session.add(login_log)
            db.session.commit()
            flash('Invalid username or password', 'danger')
    
    return render_template('auth/login.html')

@auth_bp.route('/logout')
@login_required
def logout():
    """User logout"""
    username = current_user.username
    logout_user()
    flash(f'You have been logged out, {username}', 'info')
    return redirect(url_for('auth.login'))

@auth_bp.route('/profile')
@login_required
def profile():
    """User profile page"""
    return render_template('auth/profile.html', user=current_user)

@auth_bp.route('/change-password', methods=['POST'])
@login_required
def change_password():
    """Change user password"""
    old_password = request.form.get('old_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    if not current_user.check_password(old_password):
        flash('Current password is incorrect', 'danger')
        return redirect(url_for('auth.profile'))
    
    if new_password != confirm_password:
        flash('New passwords do not match', 'danger')
        return redirect(url_for('auth.profile'))
    
    if len(new_password) < 6:
        flash('Password must be at least 6 characters', 'danger')
        return redirect(url_for('auth.profile'))
    
    current_user.set_password(new_password)
    db.session.commit()
    
    flash('Password changed successfully', 'success')
    return redirect(url_for('auth.profile'))
