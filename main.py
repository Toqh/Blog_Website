from datetime import date
from tokenize import Comment

from flask import Flask, abort, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, ForeignKey
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm



'''
Make sure the required packages are installed: 
Open the Terminal in PyCharm (bottom left). 

On Windows type:
python -m pip install -r requirements.txt

On MacOS type:
pip3 install -r requirements.txt

This will install the packages from the requirements.txt for this project.
'''

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap5(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
# TODO: Configure Flask-Login
gravatar = Gravatar(
    app,
    size=80,  # Default size of the avatar
    rating='g',  # Rating ('g', 'pg', 'r', 'x')
    default='retro',  # Default image if email has no Gravatar
    force_default=False,  # Force default image
    force_lower=False,  # Force email to lowercase
    use_ssl=True,  # Use HTTPS
    base_url=None  # Custom base URL
)
def admin_only(f):
    def wrapper(*args, **kwargs):
        if current_user.get_id() != '1':  # Check if the user ID is not '1'
            abort(403)  # Return 403 Forbidden
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__  # Preserve the original function name
    return wrapper

# CREATE DATABASE
class Base(DeclarativeBase):
    pass
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey('users.id'))

    # Relationships
    author = relationship('User', back_populates='posts')
    comments = relationship('Comments', back_populates='parent_post')


# User Table
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(250), nullable=False)

    # Relationships
    comments = relationship('Comments', back_populates='author')
    posts = relationship('BlogPost', back_populates='author')


# Comments Table
class Comments(db.Model):
    __tablename__ = 'comments'

    # Define the columns using mapped_column
    id: Mapped[int] = mapped_column(Integer, primary_key=True)  # Comment ID
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey('users.id'))  # Foreign key to users
    text: Mapped[str] = mapped_column(Text, nullable=False)  # CKEditor text (HTML content)
    post_id: Mapped[int] = mapped_column(Integer, ForeignKey('blog_posts.id'))  # Foreign key to blog_posts

    # Relationships
    author = relationship('User', back_populates='comments')
    parent_post = relationship('BlogPost', back_populates='comments')



with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods = ['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data
        name = form.name.data
        password = form.password.data
        password_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)

        if User.query.filter_by(email=email).first():
            flash('An account with this email already exists. Login.', 'danger')
            return redirect(url_for('login'))

        elif User.query.filter_by(name=name).first():
            flash('An account with this username already exists.', 'danger')
            return redirect(url_for('register'))

        # Save to database
        else:
            new_user = User(email=email, name=name, password=password_hash)
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully! Please login.', 'success')
            return redirect(url_for('login'))

    return render_template("register.html", form = form)


# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods = ['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('get_all_posts', logged_in = current_user.is_authenticated))
        else:
            flash('Invalid email or password.', 'danger')
            return redirect(url_for('login'))

    return render_template("login.html", form = form)


@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    user_id = current_user.id if current_user.is_authenticated else None

    return render_template("index.html", all_posts=posts, user_id = user_id)


# TODO: Allow logged-in users to comment on posts

@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = CommentForm()
    if form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comments(
                text=form.comment.data,
                post_id=post_id,
                author_id=current_user.id
            )
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for('show_post', post_id=post_id))
        else:
            return redirect(url_for('login'))


    requested_post = db.get_or_404(BlogPost, post_id)
    comments = Comments.query.filter_by(post_id=post_id).all()
    user_id = current_user.id if current_user.is_authenticated else None
    return render_template("post.html",form = form,
                           user_id = user_id, post=requested_post,
                           comments=comments )


# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=True, port=5002)
