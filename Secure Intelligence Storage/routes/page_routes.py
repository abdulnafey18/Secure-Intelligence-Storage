from flask import render_template, redirect, url_for, session, flash, make_response
from database.mongo_db import db # MongoDB database for file metadata
from bson.objectid import ObjectId # Initialising MongoDB database connection
from database.sql_db import get_db_connection # Establishes a connection to the SQLite database

def page_routes(app):
    # Redirect to '/homepage'
    @app.route('/')
    def root():
        return redirect('/homepage')
    # Homepage route to render the application's homepage
    @app.route('/homepage')
    def homepage():
        return render_template('homepage.html')
    # Admin dashboard route to display admin tools and user management options
    @app.route('/adminDashboard')
    def adminDashboard():
        if 'role' in session and session['role'] == 'admin':
            connection = get_db_connection()
            users = connection.execute('SELECT * FROM users').fetchall()
            connection.close()
            # Ensure the admin dashboard is not cached by the browser
            response = make_response(render_template('admin_dashboard.html', users=users))
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '-1'
            return response
        else:
            flash('Unauthorized access!', 'error')
            return redirect(url_for('login'))
    # User dashboard route to display user-specific details
    @app.route('/userDashboard')
    def userDashboard():
        if 'email' in session:
            connection = get_db_connection()
            user = connection.execute(
                'SELECT * FROM users WHERE email = ?', 
                (session['email'],)
            ).fetchone()
            connection.close()
            # Ensure the user dashboard is not cached by the browser
            if user:

                response = make_response(render_template('user_dashboard.html', user=user))
                response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
                response.headers['Pragma'] = 'no-cache'
                response.headers['Expires'] = '-1'
                return response
            else:
                flash('User not found.', 'error')
                return redirect(url_for('login'))
        else:
            flash('You need to log in first.', 'error')
            return redirect(url_for('login'))
    # This route dynamically redirects users to their dashboards based on the role admin or user
    @app.route('/dynamic_homepage')
    def dynamic_homepage():
        if 'role' in session:
            if session['role'] == 'admin':
                return redirect(url_for('adminDashboard'))  
            elif session['role'] == 'user':
                return redirect(url_for('userDashboard'))
            else:
                flash('Unknown role. Please contact support.', 'error')
                return redirect(url_for('login'))
        else:
            flash('You need to log in first.', 'error')
            return redirect(url_for('login'))
    # This route is accessible only to admins. It fetches all user data from the database and displays it for management purposes
    @app.route('/all_users')
    def all_users():
        if 'role' in session and session['role'] == 'admin':
            connection = get_db_connection()
            users = connection.execute('SELECT id, email, role FROM users').fetchall()  # Fetch user data
            connection.close()
            return render_template('all_users.html', users=users)
        else:
            flash('Unauthorized access!', 'error')
            return redirect(url_for('login'))
    @app.route('/nmap_scanner')
    def nmap_scanner():
        return render_template('nmap_scanner.html')