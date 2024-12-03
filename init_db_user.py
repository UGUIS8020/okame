from app import db, User, app
from werkzeug.security import generate_password_hash
from datetime import datetime

with app.app_context():
    # 管理者ユーザーの作成
    admin_user = User(
        email="shibuyamasahiko@gmail.com", 
        user_name="渋谷正彦", 
        display_name="まさひこ", 
        furigana="シブヤマサヒコ", 
        password=generate_password_hash("giko8020@Z", method="pbkdf2:sha256"),  # ハッシュ化に明示的に pbkdf2:sha256 を指定
        gender="male", 
        date_of_birth=datetime(1971, 11, 20), 
        administrator=True
    )
    db.session.add(admin_user)
    db.session.commit()
    print("Admin user created successfully!")

