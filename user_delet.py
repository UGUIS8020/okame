from app import db, User, app

with app.app_context():
    # User テーブル内のすべてのデータを削除
    User.query.delete()
    db.session.commit()
    print("All user data has been deleted successfully.")