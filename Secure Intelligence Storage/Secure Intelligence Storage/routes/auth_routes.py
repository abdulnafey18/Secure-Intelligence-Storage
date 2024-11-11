from flask import render_template, request, redirect, url_for, session, flash
from database.mongo_db import db
from werkzeug.security import generate_password_hash, check_password_hash
from database.mongo_db import db

def auth_routes(app):
    @app.route('/registerMenu', methods=['GET', 'POST'])
    def registerMenu():
        if request.method == 'POST':
            email = request.form['email']
            password = request.form['password']
            hashed_password = generate_password_hash(password)
            db.users.insert_one({'email': email, 'password': hashed_password})
            session['email'] = email  # Store name in session for future steps
            return redirect(url_for('set_file_password'))
        return render_template('register_menu.html')

    @app.route('/loginMenu', methods=['GET', 'POST'])
    def loginMenu():
        if request.method == 'POST':
            email = request.form['email']
            password = request.form['password']
            user = db.users.find_one({'email': email})
            if user:
                # Check if the password matches the hashed password
                if check_password_hash(user['password'], password):
                    session['email'] = email
                    return redirect(url_for('userDashboard'))
                else:
                    flash('Incorrect password. Please try again.', 'error')
            else:
                flash('email not found. Please try again or register.', 'error')
        return render_template('login_menu.html')

    @app.route('/logout')
    def logout():
        session.pop('email', None)
        return redirect(url_for('homepage'))