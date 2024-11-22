from flask import render_template, request, redirect, url_for, session, flash, send_file
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp, qrcode # For MFA implementation
from io import BytesIO # For handling QR code generation
from database.sql_db import initialize_database, insert_user, find_user_by_email, update_mfa_secret
from database.mongo_db import db # MongoDB database for file metadata
from database.sql_db import get_db_connection, find_user_by_email, update_mfa_secret, decrypt_secret

initialize_database() # Initialize the SQLite database and tables.

def auth_routes(app):
    # Enable MFA route to generate and store the MFA secret and to display a QR code.
    @app.route('/enable_mfa')
    def enable_mfa():
        if 'email' not in session:
            flash('Please log in first.', 'error')
            return redirect(url_for('login'))

        
        secret = pyotp.random_base32() # Generate a random MFA secret for the user
        update_mfa_secret(session['email'], secret) # Save the secret in the database

        # Generate an OTP URI and create a QR code for it
        otp_uri = pyotp.TOTP(secret).provisioning_uri(
            session['email'], issuer_name="Secure Intelligence Storage"
        )
        qr = qrcode.make(otp_uri) # Create QR code for scanning with google authenticator app
        buffer = BytesIO()
        qr.save(buffer, 'PNG')
        buffer.seek(0)
        return send_file(buffer, mimetype='image/png') # Send the QR code to the user
    # Registration route to handle user registration with email and hashed password
    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if request.method == 'POST':
            email = request.form['email']
            password = request.form['password']
            password_hash = generate_password_hash(password) # Hash the password for secure storage

            if find_user_by_email(email):
                flash('Email is already registered.', 'error')
                return redirect(url_for('register'))

            insert_user(email, password_hash) # Add the new user to the database
            db.users.insert_one({'email': email, 'file_password': None}) # Add user to MongoDB for file handling

            session['email'] = email # Log the user in after registration
            return redirect(url_for('set_file_password')) # Redirect to set file password
        return render_template('register_menu.html')
    # Login route to authenticate the user with email, password, and MFA
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            email = request.form['email']
            password = request.form['password']
            otp = request.form.get('otp')  
            user = find_user_by_email(email)
            # Verify credentials and MFA if enabled
            if user and check_password_hash(user['password_hash'], password):  
                if user['mfa_secret']: # Check if MFA is enabled for the user
                    decrypted_mfa_secret = decrypt_secret(user['mfa_secret'])  
                    totp = pyotp.TOTP(decrypted_mfa_secret) 
                    if not otp or not totp.verify(otp):  
                        flash('Invalid or missing OTP. Please try again.', 'error')
                        return redirect(url_for('login'))

                # Save user session and redirect based on role
                session['email'] = user['email']
                session['role'] = user['role']  

                if user['role'] == 'admin':
                    return redirect(url_for('adminDashboard'))  
                else:
                    return redirect(url_for('userDashboard'))  
            else:
                flash('Invalid credentials.', 'error')
                return redirect(url_for('login'))
        return render_template('login_menu.html')
    # Logout route for clearing the session and logging out the user
    @app.route('/logout')
    def logout():
        session.clear()
        flash('Logged out successfully.', 'success')
        return redirect(url_for('homepage'))
    # Admin-only route that allows an admin to delete a user
    @app.route('/delete_user/<int:user_id>', methods=['POST'])
    def delete_user(user_id):
        if 'role' in session and session['role'] == 'admin':
            connection = get_db_connection()
            
            connection.execute('DELETE FROM users WHERE id = ?', (user_id,))
            connection.commit()
            connection.close()

            flash('User deleted successfully!', 'success')
            return redirect(url_for('all_users'))
        else:
            flash('Unauthorized action!', 'error')
            return redirect(url_for('login'))