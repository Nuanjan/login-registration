from flask.helpers import flash
from flask_app import app
from flask import redirect, render_template, session, request, url_for
from flask_app.models.user import User
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt(app)     # we are creating an object called bcrypt,


@app.route('/')
def index():
    isShow = session["isShow"]
    print("isshow:", isShow)
    return render_template('index.html', isShow=isShow)


@app.route('/register-login', methods=['POST'])
def register_user():
    print(request.form)
    if request.form['which_form'] == "register":
        if not User.validate_user(request.form):
            session['isShow'] = request.form['which_form']
            return redirect('/')
        hashed_password = bcrypt.generate_password_hash(
            request.form['password'])
        print(hashed_password, "password")
        data = {
            "first_name": request.form['first_name'],
            "last_name": request.form['last_name'],
            "email": request.form['e_mail'],
            "password": hashed_password
        }
        session['user_id'] = User.add_user(data)
        return redirect('/user_dashboard')
    elif request.form['which_form'] == "login":
        data = {"email": request.form['e_mail']}
        # check if email exist in database
        user_in_db = User.get_user_by_email(data)
        validation_data = {
            "user_in_db": user_in_db,
            "password": request.form["password"]
        }
        print("user validation", User.validate_login_user(validation_data))
        if not User.validate_login_user(validation_data):
            session['isShow'] = request.form['which_form']
            return redirect('/')
        elif not bcrypt.check_password_hash(user_in_db.password, request.form['password']):
            print(bcrypt.check_password_hash(
                user_in_db.password, request.form['password']))
            flash("Invalid user/password")
            session['isShow'] = request.form['which_form']
            return redirect('/')
        return redirect('/user_dashboard')


@app.route('/user_dashboard')
def user_dashboard():
    if user_id in session:
         render_template('user_dashboard.html')
    else:
        render_template('index.html')
# @app.route('/user/new')
# def will_add_user():
#     isGetUser = session['isGetUser'] = 'false'
#     isAddUser = session['isAddUser'] = 'true'
#     headerText = session['header'] = "Add User"
#     isHome = session['isHome'] = "false"
#     return render_template('index.html', isGetUser=isGetUser, isAddUser=isAddUser, headerText=headerText, isHome=isHome)


# @app.route('/user/add', methods=['POST'])
# def add_user():
#     data = {
#         'first_name': request.form['first_name'],
#         'last_name': request.form['last_name'],
#         'email': request.form['email']
#     }
#     User.add_user(data)
#     return redirect('/users')


# @app.route('/show_user/<int:user_id>')
# def show_user(user_id):
#     data = {
#         'id': user_id
#     }
#     one_user = User.get_user(data)
#     return render_template('user.html', one_user=one_user)


# @app.route('/edit/<int:user_id>')
# def edit(user_id):
#     data = {
#         "id": user_id
#     }
#     one_user = User.get_user(data)
#     return render_template('edit.html', one_user=one_user)


# @app.route('/edit/update/<int:user_id>', methods=['POST'])
# def edit_user(user_id):

#     data = {
#         'id': user_id,
#         'first_name': request.form['first_name'],
#         'last_name': request.form['last_name'],
#         'email': request.form['email']
#     }
#     User.edit_user(data)
#     return redirect('/users')


# @app.route('/delete/<int:user_id>')
# def delete(user_id):
#     data = {
#         "id": user_id
#     }
#     User.delete_user(data)
#     return redirect('/users')
