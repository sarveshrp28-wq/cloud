# Cloud Security Monitoring System
## Diploma Computer Science Project

A comprehensive security monitoring system for cloud environments that detects suspicious activities, generates alerts, and provides a dashboard for security analysts.

---

## 🎯 Project Overview

This system monitors cloud-related activities in real-time and implements threat detection algorithms to identify security risks. It includes:

- **User Authentication** - Secure login system with role-based access control
- **Activity Monitoring** - Track user actions and cloud events
- **Threat Detection** - Automated detection of security anomalies
- **Alert Management** - Generate and manage security alerts
- **Dashboard & Reports** - Visual analytics and security metrics

---

## ✨ Key Features

### 1. **User Authentication & Authorization**
- Secure password hashing (bcrypt)
- Session management with Flask-Login
- Three-tier role system:
  - **Admin**: Full system access, user management
  - **Analyst**: Alert and event investigation
  - **Viewer**: Read-only dashboard access
- Account lockout after 5 failed attempts
- Remember me functionality

### 2. **Activity Monitoring**
- Log all user login attempts (success/failure)
- Track user actions (create, delete, modify)
- Record IP addresses and timestamps
- Store detailed activity information

### 3. **Threat Detection Engine**
Automated detection of:
- **Brute Force Attacks**: Multiple failed login attempts
- **Unusual Locations**: Logins from new/unusual IP addresses
- **Unusual Time Access**: Logins outside normal hours
- **Privilege Escalation**: Unauthorized admin action attempts
- **Bulk Data Access**: Unusual data download patterns

### 4. **Alert Management**
- Real-time alert generation
- Severity levels: Critical, High, Medium, Low, Info
- Alert statuses: Open, Acknowledged, Resolved
- Alert assignment to analysts
- Resolution notes and tracking

### 5. **Security Dashboard**
- Key metrics and statistics
- Alert trend charts (7-day view)
- Severity distribution
- Recent security events
- Recent login timeline
- Manual threat detection trigger

### 6. **Reports & Analytics**
- Event type distribution
- Security recommendations
- Resolution rate tracking
- Export capabilities (PDF, CSV)

### 7. **Audit Logging**
- Complete activity audit trail
- Admin action logging
- User access history

---

## 🛠️ Technology Stack

- **Backend**: Python 3.8+, Flask 2.3
- **Database**: SQLite (dev), MySQL (production)
- **Frontend**: Bootstrap 5, Chart.js
- **Authentication**: Flask-Login, bcrypt
- **ORM**: SQLAlchemy

---

## 📋 Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- (Optional) MySQL server for production

---

## 🚀 Installation & Setup

### Step 1: Clone/Extract Project
```bash
cd cloud-security-monitoring
```

### Step 2: Create Virtual Environment
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/Mac
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Configure Environment
```bash
# Copy environment template
cp .env.example .env

# Edit .env and set your configuration
# For development, defaults are fine
```

### Step 5: Initialize Database
```bash
python
```

Then in Python shell:
```python
from app import create_app
from models import db, User

app = create_app('development')
with app.app_context():
    db.create_all()
    
    # Create default admin user
    admin = User(username='admin', email='admin@example.com', role='admin')
    admin.set_password('password123')
    db.session.add(admin)
    db.session.commit()
    print("Admin user created!")
exit()
```

### Step 6: Run Application
```bash
python app.py
```

Visit: `http://localhost:5000`

---

## 👤 Demo Credentials

Use these credentials to test the system:

```
Admin Account:
  Username: admin
  Password: password123

Analyst Account:
  Username: analyst
  Password: password123

Viewer Account:
  Username: viewer
  Password: password123
```

To create demo accounts, run in Python shell:
```python
from app import create_app
from models import db, User, UserRole

app = create_app('development')
with app.app_context():
    # Create analyst
    analyst = User(username='analyst', email='analyst@example.com', role=UserRole.ANALYST)
    analyst.set_password('password123')
    db.session.add(analyst)
    
    # Create viewer
    viewer = User(username='viewer', email='viewer@example.com', role=UserRole.VIEWER)
    viewer.set_password('password123')
    db.session.add(viewer)
    
    db.session.commit()
    print("Demo users created!")
exit()
```

---

## 📊 Database Schema

### Users Table
- `id`: Primary key
- `username`: Unique username
- `email`: User email
- `password_hash`: Hashed password
- `role`: Admin, Analyst, or Viewer
- `is_active`: Account status
- `last_login`: Last login timestamp
- `failed_login_attempts`: Failed attempt counter

### Login Logs Table
- Tracks all login attempts
- Records IP, user agent, timestamp
- Success/failure status

### Activity Logs Table
- User action tracking
- Resource and action type
- IP address and timestamp
- Status (success/failure)

### Security Events Table
- Detected threats and anomalies
- Event type and severity
- Source IP and affected resource
- Raw event data (JSON)

### Alerts Table
- Generated from security events
- Severity and status
- Assignment to analysts
- Resolution notes

---

## 🔍 Threat Detection Configuration

Edit thresholds in `threats.py`:

```python
BRUTE_FORCE_THRESHOLD = 5  # Failed attempts before alert
BRUTE_FORCE_WINDOW = 15  # Time window in minutes
SUSPICIOUS_LOGIN_WINDOW = 60  # Minutes for location analysis
SUSPICIOUS_LOCATIONS_COUNT = 3  # Different IPs for alert
UNUSUAL_TIME_THRESHOLD = 22  # 10 PM (24-hour format)
```

---

## 📁 Project Structure

```
cloud-security-monitoring/
├── app.py                 # Main Flask application
├── models.py              # Database models
├── auth.py                # Authentication routes
├── threats.py             # Threat detection engine
├── requirements.txt       # Python dependencies
├── .env.example           # Environment template
├── templates/
│   ├── base.html          # Base template
│   ├── dashboard.html     # Dashboard
│   ├── reports.html       # Reports page
│   ├── auth/
│   │   ├── login.html
│   │   └── register.html
│   ├── alerts/
│   │   ├── list.html
│   │   └── detail.html
│   ├── events/
│   │   ├── list.html
│   │   └── detail.html
│   └── admin/
│       └── users.html
└── cloud_security.db      # SQLite database (auto-created)
```

---

## 🔐 Security Best Practices

1. **Change Default Secret Key**
   ```python
   # In .env
   SECRET_KEY=your-super-secret-key-here
   ```

2. **Use HTTPS in Production**
   ```python
   SESSION_COOKIE_SECURE=True
   ```

3. **Strong Passwords**
   - Minimum 6 characters
   - Encourage complexity

4. **Regular Updates**
   - Keep Flask and dependencies updated
   - Review security alerts

5. **Database Backups**
   - Backup regularly
   - Secure backup storage

---

## 🧪 Testing Features

### Test Brute Force Detection
1. Login to any account
2. Deliberately fail login 5+ times
3. Check dashboard for alert

### Test Unusual Location Detection
1. Login from different IP addresses
2. Wait for threat detection to run
3. Check alerts for unusual location warning

### Test Alert Management
1. View open alerts
2. Click "Acknowledge" to mark in progress
3. Click "Resolve" and add notes
4. Verify status changes in list view

### Run Manual Threat Detection
1. Go to Dashboard (admin only)
2. Click "Run Threat Detection" button
3. Check alerts generated

---

## 📈 Usage Workflow

### For Security Analysts

1. **Check Dashboard**
   - Review key metrics
   - Check recent events

2. **Investigate Alerts**
   - Go to Alerts page
   - Filter by status/severity
   - Click alert to view details

3. **Review Events**
   - Go to Events page
   - Click event for detailed investigation
   - View related alerts

4. **Acknowledge & Resolve**
   - Acknowledge alert when investigating
   - Add resolution notes when complete
   - Mark as resolved

5. **Generate Reports**
   - Go to Reports page
   - Review security metrics
   - Export data if needed

### For Administrators

1. **Manage Users**
   - Add new user accounts
   - Assign roles (Admin, Analyst, Viewer)
   - Deactivate accounts

2. **Review Audit Logs**
   - Track all user actions
   - Review admin changes

3. **Run Threat Detection**
   - Manually trigger detection
   - Review detected threats
   - Adjust thresholds as needed

---

## 🐛 Troubleshooting

### Database Errors
```bash
# Remove old database and recreate
rm cloud_security.db
python app.py
# Re-create admin user in Python shell
```

### Login Issues
- Check username/password spelling
- Account may be locked (5+ failed attempts)
- Check if account is active in user management

### Charts Not Displaying
- Refresh page
- Check browser console for errors
- Ensure Chart.js is loading

### Alerts Not Generating
- Run manual threat detection
- Check if events exist
- Verify threat detection thresholds

---

## 🔄 Production Deployment

### Using MySQL
1. Install MySQL server
2. Create database: `CREATE DATABASE cloud_security;`
3. Update .env:
   ```
   DATABASE_URL=mysql+mysqlconnector://user:password@localhost/cloud_security
   ```

### Using Gunicorn
```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:create_app('production')
```

### Using Nginx
```nginx
server {
    listen 80;
    server_name yourdomain.com;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## 📝 Future Enhancements

- [ ] Multi-factor authentication (MFA)
- [ ] Real-time WebSocket alerts
- [ ] Email/SMS notifications
- [ ] Machine learning anomaly detection
- [ ] API integration with cloud providers
- [ ] Dark mode UI
- [ ] Custom threat rules
- [ ] SIEM integration
- [ ] Automated response actions
- [ ] Compliance reporting (GDPR, HIPAA)

---

## 📚 Learning Resources

- **Flask Documentation**: https://flask.palletsprojects.com/
- **SQLAlchemy ORM**: https://docs.sqlalchemy.org/
- **Bootstrap 5**: https://getbootstrap.com/docs/5.0/
- **Chart.js**: https://www.chartjs.org/docs/latest/

---

## 📞 Support & Contribution

For issues or improvements:
1. Check existing documentation
2. Review code comments
3. Consult Flask/SQLAlchemy documentation
4. Test changes thoroughly

---

## 📄 License

This is a diploma project for educational purposes.

---

## ✅ Checklist for Diploma Submission

- [x] User Authentication System
- [x] Activity Monitoring & Logging
- [x] Threat Detection Engine
- [x] Alert Generation & Management
- [x] Security Dashboard
- [x] Reports & Analytics
- [x] Admin Panel
- [x] Database Design
- [x] Role-Based Access Control
- [x] Documentation

---

**Last Updated**: 2024
**Project Version**: 1.0.0
**Status**: Production Ready
