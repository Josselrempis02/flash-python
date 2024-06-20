from app import app, db

# Create an application context
app.app_context().push()

# Create all database tables
db.create_all()

print("Database tables created")
