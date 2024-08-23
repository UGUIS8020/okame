from flask import Flask
from flask import render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user,logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
import os
import boto3
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
import uuid
from flask_migrate import Migrate

from datetime import datetime
import pytz

app = Flask(__name__)

load_dotenv()

# S3クライアントの設定
s3 = boto3.client('s3',
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    region_name=os.getenv("AWS_REGION")
)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///blog.db"
app.config["SECRET_KEY"] = os.urandom(24)
app.config['S3_BUCKET'] = os.getenv("S3_BUCKET")
app.config['S3_LOCATION'] = f"https://{app.config['S3_BUCKET']}.s3.{os.getenv('AWS_REGION')}.amazonaws.com/"
db = SQLAlchemy(app)
# Flask-Migrateの設定
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)

def tokyo_time():
    return datetime.now(pytz.timezone('Asia/Tokyo'))


class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    posts = db.relationship('Post', backref='category', lazy=True)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50), nullable=False)
    body = db.Column(db.String(300), nullable=False)    
    image_url = db.Column(db.String(255), nullable=True)
    # created_at = db.Column(db.DateTime, nullable=False, default=datetime.now(pytz.timezone('Asia/Tokyo')))
    created_at = db.Column(db.DateTime, nullable=False, default=tokyo_time)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True)
    password = db.Column(db.String(128))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/")
@login_required
def index():
    # if request.method == "GET":
        # posts = Post.query.all()
    posts = Post.query.order_by(Post.created_at.desc()).all()
    return render_template("index.html", posts=posts)
    # return render_template("index.html")

@app.route("/auth", methods=["GET", "POST"])
def auth():
    if request.method == "POST":
        action = request.form.get("action")
        username = request.form.get("username")
        password = request.form.get("password")

        if action == "signup":
            # サインアップ処理
            user = User(username=username, password=generate_password_hash(password, method="pbkdf2:sha256"))
            db.session.add(user)
            db.session.commit()
            flash("アカウントが作成されました。ログインしてください。", "success")
            return redirect("/auth")
        
        elif action == "login":
            # ログイン処理
            user = User.query.filter_by(username=username).first()
            if user is not None and check_password_hash(user.password, password):
                login_user(user)
                return redirect("/")
            else:
                flash("ユーザー名かパスワードが間違っています", "error")
                return redirect("/auth")

    return render_template("auth.html")


# @app.route("/signup", methods=["GET", "POST"])
# def signup():
#     if request.method == "POST":
#         username = request.form.get("username")
#         password = request.form.get("password")
#         user = User(username=username, password=generate_password_hash(password, method="pbkdf2:sha256"))
       
#         db.session.add(user)
#         db.session.commit()

#         return redirect("/login")
#     else:
#         return render_template("signup.html")
    
# @app.route("/login", methods=["GET", "POST"])
# def login():
#     if request.method == "POST":
#         username = request.form.get("username")
#         password = request.form.get("password")

#         user = User.query.filter_by(username=username).first()
#         if user is not None and check_password_hash(user.password, password):
#             login_user(user)
#             return redirect("/")
#         else:
#             flash("ユーザー名かパスワードが間違っています", "error")
#             return redirect("/login")
#     else:
#         return render_template("login.html")
        
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/auth")


@app.route("/create", methods=["GET", "POST"])
@login_required
def create():
    if request.method == "POST":
        title = request.form.get("title")
        body = request.form.get("body")
        image = request.files.get("image")
        category_id = request.form['category_id']

        
        if image and image.filename != '': 
            original_filename = secure_filename(image.filename)
            # ファイル名にユニークなIDを追加して変更
            unique_filename = f"{uuid.uuid4().hex}_{original_filename}"
            s3.upload_fileobj(
                image,
                app.config['S3_BUCKET'],
                unique_filename
            )
            image_url = f"{app.config['S3_LOCATION']}{unique_filename}"
        else:
            image_url = None

        new_post = Post(title=title, body=body, image_url=image_url, category_id=category_id)
        db.session.add(new_post)
        db.session.commit()
        
        return redirect(url_for('index'))
    
    categories = Category.query.all()
    return render_template("create.html", categories=categories)


    
@app.route("/<int:id>/update", methods=["GET", "POST"])
@login_required
def update(id):
    post = Post.query.get(id)
    if request.method == "GET":
        return render_template("update.html", post=post)
    
    else:
        post.title = request.form.get("title")
        post.body = request.form.get("body")
        post.category_id = request.form.get("category_id")
        db.session.commit()
        return redirect("/")
    
@app.route("/<int:id>/delete")
@login_required
def delete(id):
    post = Post.query.get(id)
    db.session.delete(post)
    db.session.commit()
    return redirect("/")  


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)