# run.py
import os
from app import create_app, db
from sqlalchemy import inspect, text

app = create_app()

with app.app_context():
    # 1) переконаймося, що instance існує
    os.makedirs(app.instance_path, exist_ok=True)

    inspector = inspect(db.engine)

    # 2) створимо відсутні таблиці (включно зі 'sbom')
    required_tables = {"user", "scan_result", "sbom"}
    missing = [t for t in required_tables if not inspector.has_table(t)]

    if missing:
        print(f"DB init: missing tables {missing}. Creating…")
        db.create_all()
        print("DB init: done.")
    else:
        print("DB OK: all required tables exist.")

    # 3) легка "міграція": додати колонку user.role, якщо її нема
    user_cols = {c["name"] for c in inspector.get_columns("user")}
    if "role" not in user_cols:
        print("DB migration: adding column user.role …")
        # SQLite ALTER TABLE ADD COLUMN (без NOT NULL тут — додамо default далі)
        with db.engine.begin() as conn:
            # додамо колонку з DEFAULT і без створення індексів/триггерів
            conn.execute(text("ALTER TABLE user ADD COLUMN role VARCHAR(16)"))
            # заповнимо NULL -> 'user'
            conn.execute(text("UPDATE user SET role = 'user' WHERE role IS NULL"))
        print("DB migration: user.role added (default 'user').")

    # опціонально: перевіримо поля в sbom (на випадок старих версій)
    if inspector.has_table("sbom"):
        sbom_cols = {c["name"] for c in inspector.get_columns("sbom")}
        expected = {"id", "scan_id", "tool", "format", "created_at", "sbom_json"}
        missing_cols = expected - sbom_cols
        if missing_cols:
            print(f"Note: sbom table missing columns: {missing_cols}. "
                  f"If this was a very old DB, consider recreating or using Alembic.")

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
