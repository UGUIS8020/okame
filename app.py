from flask import Flask
from flask_wtf import FlaskForm
from flask import render_template, request, redirect, url_for, flash, abort, session
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import ValidationError, StringField, PasswordField, SubmitField, SelectField, DateField, BooleanField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Optional
import pytz
import os
import boto3
from werkzeug.utils import secure_filename
import uuid
from datetime import datetime, date
import io
from PIL import Image
from dateutil.relativedelta import relativedelta
from botocore.exceptions import ClientError
from init_db import init_tables  # init_counter_tableから変更
import logging
from dotenv import load_dotenv

# ロギングの設定
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# グローバル変数の定義
app = Flask(__name__)
login_manager = LoginManager()

def create_app():
    """アプリケーションの初期化と設定"""
    try:
        # 環境変数の読み込み
        load_dotenv()

        # シークレットキーの設定
        app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", os.urandom(24))
        
        # AWS S3の設定
        app.config['S3_BUCKET'] = os.getenv("S3_BUCKET")
        aws_region = os.getenv("AWS_REGION", "ap-northeast-1")
        app.config['S3_LOCATION'] = f"https://{app.config['S3_BUCKET']}.s3.{aws_region}.amazonaws.com/"
        
        # AWS認証情報
        aws_credentials = {
            'aws_access_key_id': os.getenv("AWS_ACCESS_KEY_ID"),
            'aws_secret_access_key': os.getenv("AWS_SECRET_ACCESS_KEY"),
            'region_name': aws_region
        }
        
        # 必須環境変数のチェック
        required_env_vars = ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "S3_BUCKET"]
        missing_vars = [var for var in required_env_vars if not os.getenv(var)]
        if missing_vars:
            raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")

        # AWSクライアントの初期化
        app.s3 = boto3.client('s3', **aws_credentials)
        app.dynamodb = boto3.client('dynamodb', **aws_credentials)
        app.dynamodb_resource = boto3.resource('dynamodb', **aws_credentials)
        
        # テーブル名の設定
        environment = os.getenv("ENVIRONMENT", "dev")
        app.table_name = f"{environment}-users"
        app.table = app.dynamodb_resource.Table(app.table_name)

        # Flask-Loginの設定
        login_manager.init_app(app)
        login_manager.login_view = 'login'
        login_manager.login_message = 'このページにアクセスするにはログインが必要です。'
        
        # DynamoDBテーブルの初期化
        init_tables()
        logger.info("Application initialized successfully")
        
        return app
        
    except Exception as e:
        logger.error(f"Failed to initialize application: {str(e)}")
        raise

create_app()  # アプリケーションの初期化

def tokyo_time():
    return datetime.now(pytz.timezone('Asia/Tokyo'))

# ユーザーローダーの設定
@login_manager.user_loader
def load_user(user_id):
    try:
        response = app.dynamodb.get_item(
            TableName=app.table_name,
            Key={'user_id': {'S': user_id}}
        )
        if 'Item' in response:
            return User.from_dynamodb_item(response['Item'])
        return None
    except Exception as e:
        app.logger.error(f"Error loading user: {str(e)}")
        return None

class RegistrationForm(FlaskForm):
    organization = SelectField('所属', choices=[('uguis', '鶯'),('other', 'その他')], default='uguis', validators=[DataRequired(message='所属を選択してください')])
    display_name = StringField('表示ネーム LINE名など', validators=[DataRequired(), Length(min=3, max=30)])
    user_name = StringField('ユーザー名', validators=[DataRequired()])
    furigana = StringField('フリガナ', validators=[DataRequired()])
    phone = StringField('電話番号', validators=[DataRequired(), Length(min=10, max=15, message='正しい電話番号を入力してください')])
    post_code = StringField('郵便番号', validators=[DataRequired(), Length(min=7, max=7, message='ハイフン無しで７桁で入力してください')])
    address = StringField('住所', validators=[DataRequired(), Length(max=100, message='住所は100文字以内で入力してください')])
    email = StringField('メールアドレス', validators=[DataRequired(), Email(message='正しいメールアドレスを入力してください')])
    email_confirm = StringField('メールアドレス確認', validators=[DataRequired(), Email(), EqualTo('email', message='メールアドレスが一致していません')])
    password = PasswordField('パスワード', validators=[DataRequired(), Length(min=8, message='パスワードは8文字以上で入力してください'), EqualTo('pass_confirm', message='パスワードが一致していません')])
    pass_confirm = PasswordField('パスワード(確認)', validators=[DataRequired()])    
    gender = SelectField('性別', choices=[('', '性別'), ('male', '男性'), ('female', '女性'), ('other', 'その他')], validators=[DataRequired()])
    date_of_birth = DateField('生年月日', format='%Y-%m-%d', validators=[DataRequired()])
    submit = SubmitField('登録')

    def validate_display_name(self, field):
        if User.query.filter_by(display_name=field.data).first():
            raise ValidationError('入力された表示ネームは既に使われています。')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('入力されたメールアドレスは既に登録されています。')
        
        
class UpdateUserForm(FlaskForm):
    organization = SelectField('所属', choices=[('uguis', '鶯'), ('other', 'その他')], validators=[DataRequired(message='所属を選択してください')])    
    display_name = StringField('表示ネーム LINE名など', validators=[DataRequired(), Length(min=3, max=30)])    
    user_name = StringField('ユーザー名', validators=[DataRequired()])    
    furigana = StringField('フリガナ',  validators=[DataRequired()])    
    phone = StringField('電話番号', validators=[DataRequired(), Length(min=10, max=15, message='正しい電話番号を入力してください')])    
    post_code = StringField('郵便番号', validators=[DataRequired(), Length(min=7, max=7, message='ハイフン無しで７桁で入力してください')])    
    address = StringField('住所', validators=[DataRequired(), Length(max=100, message='住所は100文字以内で入力してください')])    
    email = StringField('メールアドレス', validators=[DataRequired(), Email(message='正しいメールアドレスを入力してください')])    
    password = PasswordField('パスワード', validators=[Optional(),  # パスワード変更は任意
                                                  Length(min=8, message='パスワードは8文字以上で入力してください'),EqualTo('pass_confirm', message='パスワードが一致していません')])    
    pass_confirm = PasswordField('パスワード(確認)')    
    gender = SelectField('性別', choices=[('', '性別'), ('male', '男性'), ('female', '女性'), ('other', 'その他')], validators=[DataRequired()])    
    date_of_birth = DateField('生年月日', format='%Y-%m-%d', validators=[DataRequired()])    
    submit = SubmitField('更新')

    def __init__(self, user_id, dynamodb_table, *args, **kwargs):
        super(UpdateUserForm, self).__init__(*args, **kwargs)
        self.id = user_id
        self.table = dynamodb_table

    def validate_email(self, field):
        """メールアドレスの重複チェック（自分のメールアドレスは除外）"""
        try:
            response = self.table.query(
                IndexName='email-index',
                KeyConditionExpression='email = :email',
                ExpressionAttributeValues={
                    ':email': field.data
                }
            )
            
            # 検索結果があり、かつ自分以外のユーザーの場合はエラー
            if response.get('Items'):
                for item in response['Items']:
                    if item['user_id'] != self.id:
                        raise ValidationError('このメールアドレスは既に使用されています。')
                        
        except ClientError as e:
            raise ValidationError('メールアドレスの確認中にエラーが発生しました。')


class User(UserMixin):
    def __init__(self, user_id, display_name, user_name, furigana, email, password, 
                 gender, date_of_birth, post_code, address, phone, 
                 organization='uguis', administrator=False, 
                 created_at=None, updated_at=None):
        self.id = user_id  # Flask-Loginはidプロパティを使用
        self.organization = organization  # 所属を追加（デフォルト：uguis）
        self.display_name = display_name
        self.user_name = user_name
        self.furigana = furigana
        self.email = email
        self.password = password
        self.gender = gender
        self.date_of_birth = self._parse_date(date_of_birth)
        self.post_code = post_code
        self.address = address
        self.phone = phone
        self.administrator = administrator
        self.created_at = created_at or datetime.now().isoformat()
        self.updated_at = updated_at or datetime.now().isoformat()

    def _parse_date(self, date_value):
        """日付文字列またはdateオブジェクトを適切に処理"""
        if isinstance(date_value, str):
            try:
                return datetime.strptime(date_value, '%Y-%m-%d').date()
            except ValueError:
                return None
        elif isinstance(date_value, date):
            return date_value
        return None

    @property
    def age(self):
        """現在の年齢を計算"""
        if not self.date_of_birth:
            return None
        today = date.today()
        return relativedelta(today, self.date_of_birth).years

    def is_administrator(self):
        """管理者権限の確認"""
        return self.administrator

    @staticmethod
    def from_dynamodb_item(item):
        """DynamoDBのitemからUserオブジェクトを生成"""
        try:
            return User(
                user_id=item.get('user_id', {}).get('S'),
                organization=item.get('organization', {}).get('S', 'uguis'),  # デフォルト値を設定
                display_name=item.get('display_name', {}).get('S'),
                user_name=item.get('user_name', {}).get('S'),
                furigana=item.get('furigana', {}).get('S'),
                email=item.get('email', {}).get('S'),
                password=item.get('password', {}).get('S'),
                gender=item.get('gender', {}).get('S'),
                date_of_birth=item.get('date_of_birth', {}).get('S'),
                post_code=item.get('post_code', {}).get('S'),
                address=item.get('address', {}).get('S'),
                phone=item.get('phone', {}).get('S'),
                administrator=item.get('administrator', {}).get('BOOL', False),
                created_at=item.get('created_at', {}).get('S'),
                updated_at=item.get('updated_at', {}).get('S')
            )
        except Exception as e:
            print(f"Error creating User from DynamoDB item: {str(e)}")
            return None

    def to_dynamodb_item(self):
        """UserオブジェクトをDynamoDB形式に変換"""
        return {
            'user_id': {'S': str(self.id)},
            'organization': {'S': self.organization},  # 所属を追加
            'display_name': {'S': self.display_name},
            'user_name': {'S': self.user_name},
            'furigana': {'S': self.furigana},
            'email': {'S': self.email},
            'password': {'S': self.password},
            'gender': {'S': self.gender},
            'date_of_birth': {'S': self.date_of_birth.strftime('%Y-%m-%d') if self.date_of_birth else ''},
            'post_code': {'S': self.post_code},
            'address': {'S': self.address},
            'phone': {'S': self.phone},
            'administrator': {'BOOL': self.administrator},
            'created_at': {'S': self.created_at},
            'updated_at': {'S': self.updated_at}
        }

    def to_dict(self):
        """UserオブジェクトをJSONシリアライズ可能な辞書に変換"""
        return {
            'user_id': str(self.id),
            'organization': self.organization,
            'display_name': self.display_name,
            'user_name': self.user_name,
            'furigana': self.furigana,
            'email': self.email,
            'gender': self.gender,
            'date_of_birth': self.date_of_birth.strftime('%Y-%m-%d') if self.date_of_birth else None,
            'post_code': self.post_code,
            'address': self.address,
            'phone': self.phone,
            'administrator': self.administrator,
            'age': self.age,
            'created_at': self.created_at,
            'updated_at': self.updated_at
        }

    def __repr__(self):
        return f'<User {self.display_name} ({self.organization})>'


# DynamoDBからデータを取得してUserインスタンスを作成する関数
def get_user_from_dynamodb(user_id):
    try:
        # DynamoDBからユーザーデータを取得
        response = dynamodb.get_item(
            TableName=table_name,
            Key={"user_id": {"S": user_id}}
        )
        
        # データが存在しない場合の処理
        if 'Item' not in response:
            print("User not found in DynamoDB.")
            return None

        item = response['Item']

        # DynamoDBのデータをUserクラスのインスタンスに変換
        user = User(
            display_name=item['display_name']['S'],
            user_name=item['user_name']['S'],
            furigana=item['furigana']['S'],
            email=item['email']['S'],
            password=item['password']['S'],
            gender=item['gender']['S'],
            date_of_birth=datetime.strptime(item['date_of_birth']['S'], '%Y-%m-%d').date(),
            post_code=item['post_code']['S'],
            address=item['address']['S'],
            phone=item['phone']['S'],
            administrator=item['administrator']['BOOL']
        )
        
        return user

    except Exception as e:
        print(f"Error fetching user from DynamoDB: {str(e)}")
        return None    

class LoginForm(FlaskForm):
    email = StringField(
        'メールアドレス',
        validators=[
            DataRequired(message='メールアドレスを入力してください'),
            Email(message='正しいメールアドレスの形式で入力してください')
        ]
    )
    
    password = PasswordField(
        'パスワード',
        validators=[
            DataRequired(message='パスワードを入力してください')
        ]
    )
    
    remember = BooleanField('ログイン状態を保持する')
    submit = SubmitField('ログイン')

    def __init__(self, dynamodb_table=None, *args, **kwargs):
        """
        Args:
            dynamodb_table: DynamoDBのテーブルインスタンス（オプショナル）
        """
        super(LoginForm, self).__init__(*args, **kwargs)
        self.table = dynamodb_table
        self.user = None  # self.userを初期化

    def validate_email(self, field):
        """メールアドレスの存在確認"""
        try:
            # メールアドレスでユーザーを検索
            response = self.table.query(
                IndexName='email-index',
                KeyConditionExpression='email = :email',
                ExpressionAttributeValues={
                    ':email': field.data
                }
            )
            
            items = response.get('Items', [])
            if not items:
                raise ValidationError('このメールアドレスは登録されていません')
            
            # ユーザー情報を保存（パスワード検証で使用）
            self.user = items[0]
            
        except Exception as e:
            raise ValidationError('ログイン処理中にエラーが発生しました')

    def validate_password(self, field):
        """パスワードの検証"""
        if self.user is None:
            raise ValidationError('先にメールアドレスを確認してください')
            
        if not check_password_hash(self.user['password'], field.data):
            raise ValidationError('パスワードが正しくありません')

    def get_user(self):
        """ログイン成功時のユーザー情報を返す"""
        return self.user

@app.route("/")
@login_required
def index():    
    posts = Post.query.order_by(Post.created_at.desc()).all()
    return render_template("index.html", posts=posts)
    

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            current_time = datetime.now().isoformat()
            hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
            user_id = str(uuid.uuid4())

            # メールアドレスの重複チェック用のクエリ
            email_check = dynamodb.query(
                TableName=table_name,
                IndexName='email-index',
                KeyConditionExpression='email = :email',
                ExpressionAttributeValues={
                    ':email': {'S': form.email.data}
                }
            )

            if email_check.get('Items'):
                app.logger.warning(f"Duplicate email registration attempt: {form.email.data}")
                flash('このメールアドレスは既に登録されています。', 'error')
                return redirect(url_for('signup'))

            # ユーザーの保存
            response = dynamodb.put_item(
                TableName=table_name,
                Item={
                    "user_id": {"S": user_id},
                    "organization": {"S": form.organization.data},  # 所属を追加
                    "address": {"S": form.address.data},
                    "administrator": {"BOOL": False},
                    "created_at": {"S": current_time},
                    "date_of_birth": {"S": form.date_of_birth.data.strftime('%Y-%m-%d')},
                    "display_name": {"S": form.display_name.data},
                    "email": {"S": form.email.data},
                    "furigana": {"S": form.furigana.data},
                    "gender": {"S": form.gender.data},
                    "password": {"S": hashed_password},
                    "phone": {"S": form.phone.data},
                    "post_code": {"S": form.post_code.data},
                    "updated_at": {"S": current_time},
                    "user_name": {"S": form.user_name.data}
                },
                ReturnValues="NONE"
            )

            # ログ出力を詳細に
            app.logger.info(f"New user created - ID: {user_id}, Organization: {form.organization.data}, Email: {form.email.data}")
            
            # 成功メッセージ
            flash('アカウントが作成されました！ログインしてください。', 'success')
            return redirect(url_for('login'))
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            
            app.logger.error(f"DynamoDB error - Code: {error_code}, Message: {error_message}")
            
            if error_code == 'ConditionalCheckFailedException':
                flash('このメールアドレスは既に登録されています。', 'error')
            elif error_code == 'ValidationException':
                flash('入力データが無効です。', 'error')
            elif error_code == 'ResourceNotFoundException':
                flash('システムエラーが発生しました。', 'error')
                app.logger.critical(f"DynamoDB table not found: {table_name}")
            else:
                flash('アカウント作成中にエラーが発生しました。', 'error')
                
            return redirect(url_for('signup'))
        
        except Exception as e:
            app.logger.error(f"Unexpected error during signup: {str(e)}", exc_info=True)
            flash('予期せぬエラーが発生しました。時間をおいて再度お試しください。', 'error')
            return redirect(url_for('signup'))
            
    # フォームのバリデーションエラーの場合
    if form.errors:
        app.logger.warning(f"Form validation errors: {form.errors}")
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'{form[field].label.text}: {error}', 'error')
    
    return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(dynamodb_table=app.table)  # ここでテーブルを渡す
    if form.validate_on_submit():
        user = user.query.filter_by(email=form.email.data).first()
        if user is not None:
            if user.
        # ログイン成功時の処理
        return redirect(url_for('index'))
    return render_template('login.html', form=form)

        
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/login")


@app.route("/user_maintenance", methods=["GET", "POST"])
@login_required
def user_maintenance():
    try:
        # シンプルにすべてのユーザーを取得
        response = dynamodb.scan(
            TableName=table_name
        )
        
        # デバッグ用にデータ構造を確認
        print("DEBUG: Response:", response)
        
        users = response.get('Items', [])
        
        # デバッグ用にユーザーデータを確認
        print("DEBUG: Users:", users)

        return render_template(
            "user_maintenance.html",
            users=users,
            page=1,
            has_next=False
        )

    except ClientError as e:
        app.logger.error(f"DynamoDB error: {str(e)}")
        flash('ユーザー情報の取得に失敗しました。', 'error')
        return redirect(url_for('index'))


@app.route('/<string:user_id>/account', methods=['GET', 'POST'])  # UUIDは文字列なのでintからstringに変更
@login_required
def account(user_id):
    # DynamoDBからユーザー情報を取得
    try:
        response = dynamodb.get_item(
            TableName=table_name,
            Key={
                'user_id': {'S': user_id}
            }
        )
        user = response.get('Item')
        if not user:
            abort(404)
            
        # 現在のユーザーが対象ユーザーまたは管理者であることを確認
        if user['user_id']['S'] != current_user.get_id() and not current_user.is_administrator:
            abort(403)

        form = UpdateUserForm(user_id)
        
        if form.validate_on_submit():
            current_time = datetime.now().isoformat()
            
            # パスワードが入力された場合はハッシュ化
            update_expression_parts = []
            expression_values = {}
            
            # 更新する項目を設定
            if form.user_name.data:
                update_expression_parts.append("user_name = :user_name")
                expression_values[':user_name'] = {'S': form.user_name.data}
                
            if form.email.data:
                update_expression_parts.append("email = :email")
                expression_values[':email'] = {'S': form.email.data}
                
            if form.password.data:
                hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
                update_expression_parts.append("password = :password")
                expression_values[':password'] = {'S': hashed_password}

            # 更新日時は常に更新
            update_expression_parts.append("updated_at = :updated_at")
            expression_values[':updated_at'] = {'S': current_time}

            # DynamoDBを更新
            response = dynamodb.update_item(
                TableName=table_name,
                Key={
                    'user_id': {'S': user_id}
                },
                UpdateExpression="SET " + ", ".join(update_expression_parts),
                ExpressionAttributeValues=expression_values,
                ReturnValues="UPDATED_NEW"
            )
            
            flash('ユーザーアカウントが更新されました', 'success')
            return redirect(url_for('user_maintenance'))
            
        elif request.method == 'GET':
            # フォームに現在の値を設定
            form.user_name.data = user.get('user_name', {}).get('S', '')
            form.email.data = user.get('email', {}).get('S', '')
            
        return render_template('account.html', form=form)
        
    except ClientError as e:
        app.logger.error(f"DynamoDB error: {str(e)}")
        flash('データベースエラーが発生しました。', 'error')
        return redirect(url_for('user_maintenance'))


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


            # 画像を読み込む
            img = Image.open(image)
            max_width = 1500  # 最大横幅を1500pxに設定

            # 画像の横幅が1500pxを超えている場合に縮小
            if img.width > max_width:
                # アスペクト比を維持したままリサイズ
                new_height = int((max_width / img.width) * img.height)                
                img = img.resize((max_width, new_height), Image.LANCZOS)

            # リサイズされた画像をバイトIOオブジェクトに保存
            img_byte_arr = io.BytesIO()
            img.save(img_byte_arr, format='JPEG')
            img_byte_arr.seek(0)

             # リサイズされた画像をS3にアップロード
            s3.upload_fileobj(
                img_byte_arr,
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
    

@app.route('/category_maintenance', methods=['GET', 'POST'])
@login_required
def category_maintenance():
    page = request.args.get('page', 1, type=int)
    blog_categories = BlogCategory.query.order_by(BlogCategory.id.asc()).paginate(page=page, per_page=10)
    form = BlogCategoryForm()
    if form.validate_on_submit():
        blog_category = BlogCategory(category=form.category.data)
        db.session.add(blog_category)
        db.session.commit()
        flash('ブログカテゴリが追加されました')
        return redirect(url_for('category_maintenance'))
    elif form.errors:
        form.category.data = ""
        flash(form.errors['category'][0])
    return render_template('category_maintenance.html', blog_categories=blog_categories, form=form)
                            

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