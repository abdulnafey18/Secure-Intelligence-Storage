from flask import render_template, redirect, url_for, session, flash
from database.mongo_db import db
from bson.objectid import ObjectId

def page_routes(app):
    @app.route('/')
    def homepage():
        return render_template('homepage.html')

    @app.route('/adminDashboard')
    def adminDashboard():
        if 'role' in session and session['role'] == 'admin':
            users = db.users.find()
            return render_template('admin_dashboard.html', users=users)
        else:
            flash('Unauthorized access!', 'error')
            return redirect(url_for('loginMenu'))

    @app.route('/userDashboard')
    def userDashboard():
        if 'email' in session:
            user = db.users.find_one({'email': session['email']})
            if user:
                return render_template('user_dashboard.html', user=user)
            else:
                flash('User not found.', 'error')
                return redirect(url_for('loginMenu'))
        else:
            flash('You need to log in first.', 'error')
            return redirect(url_for('loginMenu'))
        
    @app.route('/dynamic_homepage')
    def dynamic_homepage():
        if 'role' in session:
            if session['role'] == 'admin':
                return redirect(url_for('adminDashboard'))  
            elif session['role'] == 'user':
                return redirect(url_for('userDashboard'))
            else:
                flash('Unknown role. Please contact support.', 'error')
                return redirect(url_for('loginMenu'))
        else:
            flash('You need to log in first.', 'error')
            return redirect(url_for('loginMenu'))
    
    @app.route('/all_users')
    def all_users():
        if 'role' in session and session['role'] == 'admin':
            users = db.users.find()  # Retrieve all user data
            return render_template('all_users.html', users=users)
        else:
            flash('Unauthorized access!', 'error')
            return redirect(url_for('loginMenu'))