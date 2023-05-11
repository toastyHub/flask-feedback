from flask import Flask, render_template, redirect, session, flash
from flask_debugtoolbar import DebugToolbarExtension
from models import db, connect_db, User, Feedback
from sqlalchemy.exc import IntegrityError
from forms import RegisterForm, LoginForm, FeedbackForm, DeleteForm
from werkzeug.exceptions import Unauthorized

app = Flask(__name__)

app.app_context().push()

app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql:///feedback"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False
app.config['SECRET_KEY'] ='toasty'
app.config['SQLALCHEMY_ECHO'] = True

connect_db(app)

toolbar = DebugToolbarExtension(app)

@app.route('/')
def index():
    return redirect("/register")


@app.route('/register', methods=['GET', 'POST'])
def register():
    
    """
    Route: /register
    Methods: GET, POST
    Description: Endpoint for user registration.

    GET Method:
        - Renders the registration form template for users to input their details.

    POST Method:
        - Registers a new user based on the submitted form data.
        - If the registration is successful, the user is redirected to their profile page.
        - If the username already exists, an error message is displayed on the registration form.

    Returns:
        - GET: Rendered registration form template.
        - POST:
            - If successful: Redirect to the user's profile page.
            - If username already exists: Rendered registration form template with an error message.

    Form Fields:
        - username (str): The username for the new user.
        - password (str): The password for the new user's account.
        - email (str): The email address for the new user.
        - first_name (str): The first name of the new user.
        - last_name (str): The last name of the new user.

    """
    
    form = RegisterForm()
    
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        email = form.email.data
        first_name = form.first_name.data
        last_name = form.last_name.data
        user = User.register(username, password, email, first_name, last_name)
        try:
            db.session.commit()
            session['username'] = user.username
            return redirect(f'/users/{user.username}')
        except IntegrityError:
            form.username.errors.append('Username already exists.')
            return render_template('register.html', form=form)
        
    else:
        return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    
    """
        Route: /login
        Methods: GET, POST
        Description: Endpoint for user login.

        GET Method:
            - Renders the login form template for users to enter their login credentials.

        POST Method:
            - Authenticates the user based on the submitted form data.
            - If the login is successful, the user is redirected to their profile page.
            - If the username or password is invalid, an error message is displayed on the login form.

        Returns:
            - GET: Rendered login form template.
            - POST:
                - If successful: Redirect to the user's profile page.
                - If invalid username or password: Rendered login form template with an error message.

        Form Fields:
            - username (str): The username associated with the user's account.
            - password (str): The password for the user's account.

    """
    
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        user = User.authenticate(username, password)
        if user:
            flash(f"Welcome back, {user.username}!")
            session['username'] = user.username
            return redirect(f'/users/{user.username}')
        else:
            form.username.errors = ['Invalid username or password.']
    return render_template('login.html', form=form)

@app.route('/users/<username>')
def user(username):
    
    """
        Route: /users/<username>
        Methods: GET
        Description: Endpoint for displaying a user's profile.

        Parameters:
            - username (str): The username of the user whose profile is being accessed.

        Returns:
            - Rendered template displaying the user's profile.
    
        Exceptions:
            - Unauthorized: If the user is not logged in or accessing a profile other than their own.

        Template Variables:
            - user (User): The user object corresponding to the provided username.
            - form (DeleteForm): The form object used for user deletion.

    """
    
    if "username" not in session or username != session['username']:
        raise Unauthorized()
    user = User.query.get(username)
    form = DeleteForm()
    
    return render_template("show.html", user=user, form=form)
    
    
@app.route("/users/<username>/delete", methods=["POST"])
def remove_user(username):
    
    """
        Route: /users/<username>/delete
        Methods: POST
        Description: Endpoint for removing a user's account.

        Parameters:
            - username (str): The username of the user whose account is being deleted.

        Returns:
            - Redirects the user to the login page after successfully deleting their account.

        Exceptions:
            - Unauthorized: If the user is not logged in or attempting to delete a profile other than their own.
    """
    
    if "username" not in session or username != session['username']:
        raise Unauthorized()
    
    user = User.query.get(username)
    db.session.delete(user)
    db.session.commit()
    session.pop("username")

    return redirect("/login")


@app.route("/users/<username>/feedback/new", methods=["GET", "POST"])
def new_feedback(username):
    
    """
        Route: /users/<username>/feedback/new
        Methods: GET, POST
        Description: Endpoint for adding new feedback for a user.

        Parameters:
            - username (str): The username of the user to whom the feedback is being provided.

        Returns:
            - GET: Rendered template for adding new feedback.
            - POST: Redirects to the user's profile page after successfully adding the feedback.

        Exceptions:
            - If the user is not logged in or attempting to add feedback for a profile other than their own.

        Form Fields:
            - title (str): The title of the feedback.
            - content (str): The content or message of the feedback.
    """

    if "username" not in session or username != session['username']:
        raise Unauthorized()

    form = FeedbackForm()

    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data

        feedback = Feedback(
            title=title,
            content=content,
            username=username,
        )

        db.session.add(feedback)
        db.session.commit()

        return redirect(f"/users/{feedback.username}")

    else:
        return render_template("new.html", form=form)
    
@app.route("/feedback/<int:feedback_id>/update", methods=["GET", "POST"])
def update_feedback(feedback_id):
    
    """
        Route: /feedback/<int:feedback_id>/update
        Methods: GET, POST
        Description: Endpoint for updating existing feedback.

        Parameters:
            - feedback_id (int): The ID of the feedback being updated.

        Returns:
            - GET: Rendered template for editing the feedback.
            - POST: Redirects to the user's profile page after successfully updating the feedback.

        Exceptions:
            - Unauthorized: If the user is not logged in or attempting to update feedback that does not belong to them.

        Form Fields:
            - title (str): The updated title of the feedback.
            - content (str): The updated content or message of the feedback.
    """
    
    feedback = Feedback.query.get(feedback_id)

    if "username" not in session or feedback.username != session['username']:
        raise Unauthorized()

    form = FeedbackForm(obj=feedback)

    if form.validate_on_submit():
        feedback.title = form.title.data
        feedback.content = form.content.data

        db.session.commit()

        return redirect(f"/users/{feedback.username}")

    return render_template("edit.html", form=form, feedback=feedback)


@app.route("/feedback/<int:feedback_id>/delete", methods=["POST"])
def delete_feedback(feedback_id):
    
    """
        Route: /feedback/<int:feedback_id>/delete
        Methods: POST
        Description: Endpoint for deleting existing feedback.

        Parameters:
            - feedback_id (int): The ID of the feedback being deleted.

        Returns:
            - Redirects to the user's profile page after successfully deleting the feedback.

        Exceptions:
            - If the user is not logged in or attempting to delete feedback that does not belong to them.
    """
    
    feedback = Feedback.query.get(feedback_id)
    if "username" not in session or feedback.username != session['username']:
        raise Unauthorized()

    form = DeleteForm()

    if form.validate_on_submit():
        db.session.delete(feedback)
        db.session.commit()

    return redirect(f"/users/{feedback.username}")


@app.route('/logout')
def logout():
    
    """
        Route: /logout
        Methods: GET
        escription: Endpoint for logging out the current user.

        Returns:
            - Redirects to the homepage after successfully logging out.
    """
    
    session.pop('username')
    flash('You have successfully logged out!')
    return redirect('/')