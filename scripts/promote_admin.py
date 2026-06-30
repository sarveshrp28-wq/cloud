from app import create_app
from models import db, User, UserRole

app = create_app()
with app.app_context():
    u = User.query.filter_by(username='admin').first()
    if not u:
        u = User(username='admin', email='admin@example.com', role=UserRole.ADMIN)
        u.set_password('password123')
        db.session.add(u)
        db.session.commit()
        print("Created admin user: admin (password: password123)")
    else:
        u.role = UserRole.ADMIN
        db.session.commit()
        print(f"User exists; role set to: {u.role.value}")
