from flask import Flask, render_template, redirect, url_for, session, flash, request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from forms import RegistrationForm, LoginForm,  FeedbackForm
from flask_bcrypt import Bcrypt


from models import db, connect_db, User, Feedback

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql:///feedback'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = True
bcrypt = Bcrypt(app)

db.init_app(app)

with app.app_context():
    db.create_all()

app.config['SECRET_KEY'] = "I'LL NEVER TELL!!"


### REG CODE

@app.route('/')
def index():
    return redirect(url_for('register'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(
            username=form.username.data,
            password=hashed_password,
            email=form.email.data,
            first_name=form.first_name.data,
            last_name=form.last_name.data
        )
        db.session.add(new_user)
        db.session.commit()
        session['username'] = new_user.username
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            session['username'] = user.username
            return redirect(url_for('user_profile', username=user.username))
        else:
            flash('Login failed. Please check your username and password.')
    return render_template('login.html', form=form)

@app.route('/users/<username>')
def user_profile(username):
    # Check if the user is logged in
    user_id = session.get('username')
    if user_id is None:
        return redirect(url_for('login'))

    # Retrieve the user's information by their username
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('User not found.', 'danger')
        return redirect(url_for('login'))

    return render_template('user.html', user=user)

@app.route('/logout')
def logout():
    # Clear user information from the session
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/users/<username>/delete', methods=['POST'])
def delete_user(username):
    # Check if the user is logged in
    if 'username' in session and session['username'] == username:
        user = User.query.filter_by(username=username).first()
        if user:
            # Delete all feedback associated with the user
            Feedback.query.filter_by(username=username).delete()
            # Delete the user
            db.session.delete(user)
            db.session.commit()
            # Clear the user information from the session
            session.pop('username', None)
            flash('Your account and all associated feedback have been deleted.', 'success')
        else:
            flash('User not found.', 'danger')
    else:
        flash('You are not authorized to delete this account.', 'danger')

    return redirect(url_for('login'))



### FEEDBACK CODE

@app.route('/users/<username>/feedback/add', methods=['GET', 'POST'])
def add_feedback(username):
    # Check if the user is logged in
    username = session.get('username')  # Change user_id to username here
    if username is None:
        flash('You must be logged in to add feedback.', 'danger')
        return redirect(url_for('login'))

    # Check if the user exists and matches the provided username
    user = User.query.filter_by(username=username).first()
    if user is None or user.username != username:  
        flash('User not found or unauthorized to add feedback.', 'danger')
        return redirect(url_for('user_profile', username=username))

    form = FeedbackForm()
    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data

        feedback = Feedback(title=title, content=content, username=username)
        db.session.add(feedback)
        db.session.commit()
        flash('Feedback added successfully!', 'success')
        return redirect(url_for('user_profile', username=username))

    return render_template('add_feedback.html', form=form, username=username)

@app.route('/feedback/<int:feedback_id>/update', methods=['GET'])
def edit_feedback(feedback_id):
    feedback = Feedback.query.get_or_404(feedback_id)

    # Check if the user is logged in and if they are the author of the feedback
    username = session.get('username')
    if username is None or feedback.username != username:
        flash('You are not authorized to edit this feedback.', 'danger')
        return redirect(url_for('user_profile', username=feedback.username))

    form = FeedbackForm(obj=feedback)
    return render_template('edit_feedback.html', form=form, feedback=feedback)

@app.route('/feedback/<int:feedback_id>/update', methods=['POST'])
def update_feedback(feedback_id):
    feedback = Feedback.query.get_or_404(feedback_id)

    # Check if the user is logged in and if they are the author of the feedback
    username = session.get('username')
    if username is None or feedback.username != username:
        flash('You are not authorized to update this feedback.', 'danger')
        return redirect(url_for('user_profile', username=feedback.username))

    form = FeedbackForm()
    if form.validate_on_submit():
        feedback.title = form.title.data
        feedback.content = form.content.data
        db.session.commit()
        flash('Feedback updated successfully!', 'success')
    else:
        flash('Feedback update failed. Please check the form.', 'danger')

    return redirect(url_for('user_profile', username=feedback.username))


@app.route('/feedback/<int:feedback_id>/delete', methods=['POST'])
def delete_feedback(feedback_id):
    feedback = Feedback.query.get_or_404(feedback_id)

    # Check if the user is logged in and if they are the author of the feedback
    username = session.get('username')
    if username is None or feedback.username != username:
        flash('You are not authorized to delete this feedback.', 'danger')
    else:
        db.session.delete(feedback)
        db.session.commit()
        flash('Feedback deleted successfully!', 'success')

    return redirect(url_for('user_profile', username=feedback.username))






if __name__ == '__main__':
    app.run(debug=True)