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

    @app.route('/notifications')
    def notifications():
        # Fetch notifications for the current user (sender)
        sender_email = session['email']
        notifications = db.access_requests.find({'sender': sender_email})

        return render_template('notifications.html', notifications=notifications)

    @app.route('/allow_access/<notification_id>', methods=['POST'])
    def allow_access(notification_id):
        if 'email' not in session:
            return redirect(url_for('loginMenu'))

        # Retrieve the shared file's ID from the notification
        notification = db.access_requests.find_one({'_id': ObjectId(notification_id)})
        shared_file_id = notification['shared_file_id']

        # Update the status of the shared file to "approved" in the shared_files collection
        db.shared_files.update_one({'_id': ObjectId(shared_file_id)}, {'$set': {'status': 'approved'}})

        # Delete the notification from the access_requests collection
        db.access_requests.delete_one({'_id': ObjectId(notification_id)})

        # Redirect back to the notifications page
        return redirect(url_for('notifications'))

    @app.route('/deny_access/<notification_id>', methods=['POST'])
    def deny_access(notification_id):
        if 'email' not in session:
            return redirect(url_for('loginMenu'))

        # Retrieve the shared file's ID from the notification
        notification = db.access_requests.find_one({'_id': ObjectId(notification_id)})
        shared_file_id = notification['shared_file_id']

        # Update the status of the shared file to "pending" in the shared_files collection
        db.shared_files.update_one({'_id': ObjectId(shared_file_id)}, {'$set': {'status': 'pending'}})

        # Delete the notification from the access_requests collection
        db.access_requests.delete_one({'_id': ObjectId(notification_id)})

        # Redirect back to the notifications page
        return redirect(url_for('notifications'))