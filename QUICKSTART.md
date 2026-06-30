# 🚀 Quick Start Guide

## 5-Minute Setup

### 1. **Install Dependencies**
```bash
pip install -r requirements.txt
```

### 2. **Create Database**
```bash
python
```

In Python:
```python
from app import create_app
from models import db, User, UserRole

app = create_app('development')
with app.app_context():
    db.create_all()
    admin = User(username='admin', email='admin@example.com', role=UserRole.ADMIN)
    admin.set_password('password123')
    db.session.add(admin)
    db.session.commit()
    print("✅ Database initialized!")
exit()
```

### 3. **Run Application**
```bash
python app.py
```

### 4. **Access Dashboard**
Open browser: `http://localhost:5000`

**Login with:**
- Username: `admin`
- Password: `password123`

---

## 📊 What to Try First

### 1. **Explore Dashboard**
- View key metrics
- Check recent events
- See login timeline

### 2. **Test Brute Force Detection**
```
1. Logout (click profile → Logout)
2. Try wrong password 5+ times
3. Go back to dashboard
4. Check "Open Alerts" count increased
```

### 3. **Create Additional Users**
```python
# In Python shell
from app import create_app
from models import db, User, UserRole

app = create_app('development')
with app.app_context():
    analyst = User(username='analyst', email='analyst@example.com', role=UserRole.ANALYST)
    analyst.set_password('password123')
    db.session.add(analyst)
    
    viewer = User(username='viewer', email='viewer@example.com', role=UserRole.VIEWER)
    viewer.set_password('password123')
    db.session.add(viewer)
    
    db.session.commit()
    print("✅ Demo users created!")
exit()
```

### 4. **Test Different Roles**
- **Admin**: Full access to everything
- **Analyst**: Manage alerts & events
- **Viewer**: Read-only access

### 5. **View Alerts**
- Click "Alerts" in sidebar
- Filter by status or severity
- Click alert to see details
- Click "Acknowledge" or "Resolve"

### 6. **Check Events**
- Click "Events" in sidebar
- See detected security issues
- Click event for full details

### 7. **View Reports**
- Click "Reports" in sidebar
- See 7-day statistics
- View security recommendations

---

## 🔧 Key Files to Modify

### Add Threat Detection Rules
Edit `threats.py` - Add new `detect_*()` methods

### Change Alert Thresholds
Edit `threats.py` - Modify `BRUTE_FORCE_THRESHOLD`, `UNUSUAL_TIME_THRESHOLD`, etc.

### Customize Dashboard
Edit `templates/dashboard.html` - Modify charts and widgets

### Add Admin Features
Edit `app.py` - Add new routes with `@admin_required` decorator

---

## 📁 File Descriptions

| File | Purpose |
|------|---------|
| `app.py` | Main Flask application & routes |
| `models.py` | Database tables & relationships |
| `auth.py` | Login, registration, role checking |
| `threats.py` | Threat detection algorithms |
| `requirements.txt` | Python package dependencies |
| `.env` | Configuration settings |
| `templates/` | HTML templates |

---

## 🐛 Common Issues & Solutions

### Can't Login
```
❌ "Invalid username or password"
✅ Check spelling, default is admin/password123
```

### Database Locked
```
❌ "database is locked"
✅ Kill Python processes and delete cloud_security.db, restart
```

### Port Already In Use
```
❌ "Address already in use"
✅ Change app.py: app.run(port=5001)
```

### Templates Not Found
```
❌ "TemplateNotFound"
✅ Ensure you're running from correct directory
```

---

## 📚 Next Steps

1. **Study the Code**
   - Read comments in each file
   - Understand database schema
   - Review threat detection logic

2. **Customize Features**
   - Add your own threat detection
   - Modify dashboard metrics
   - Create custom reports

3. **Deploy to Production**
   - Switch to MySQL
   - Use Gunicorn server
   - Set SECRET_KEY in .env
   - Enable HTTPS

4. **Add Advanced Features**
   - Email alerts
   - Machine learning detection
   - API endpoints
   - Real-time dashboards

---

## 💡 Pro Tips

✨ **Tip 1**: Run threat detection manually from dashboard to see it in action

✨ **Tip 2**: Filter alerts by severity to focus on critical issues

✨ **Tip 3**: Check "Admin > Audit Logs" to see all system actions

✨ **Tip 4**: Use the browser console (F12) to debug frontend issues

✨ **Tip 5**: Keep .env file with sensitive data away from version control

---

## 🎯 Project Goals Achieved

✅ User Authentication & Authorization
✅ Activity Monitoring & Logging  
✅ Threat Detection Engine
✅ Real-time Alert System
✅ Interactive Dashboard
✅ Security Reports
✅ Admin Panel
✅ Database Design
✅ Role-Based Access Control

---

**Happy Coding! 🎓**

For questions, refer to README.md for detailed documentation.
