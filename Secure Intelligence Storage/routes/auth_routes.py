from flask import render_template, request, redirect, url_for, session, flash, send_file
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp, qrcode, re 
from io import BytesIO 
from database.sql_db import initialize_database, insert_user, find_user_by_email, update_mfa_secret
from database.mongo_db import db # MongoDB database for file metadata
from database.mongo_db import add_log
from database.sql_db import get_db_connection, find_user_by_email, update_mfa_secret, decrypt_secret

initialize_database() # Initialize the SQLite database and tables.

def auth_routes(app):
    # Enable MFA route to generate and store the MFA secret and to display a QR code.
    @app.route('/enable_mfa')
    def enable_mfa():
        if 'email' not in session:
            flash('Please log in first.', 'error')
            return redirect(url_for('login'))

        # Generate a new MFA secret
        secret = pyotp.random_base32()
        
        # Store MFA secret in the database **securely** for the user
        update_mfa_secret(session['email'], secret)

        # Generate OTP URI and QR code
        otp_uri = pyotp.TOTP(secret).provisioning_uri(
            session['email'], issuer_name="Secure Intelligence Storage"
        )
        qr = qrcode.make(otp_uri)
        buffer = BytesIO()
        qr.save(buffer, 'PNG')
        buffer.seek(0)

        return send_file(buffer, mimetype='image/png')
    # Function to validate a strong password
    def is_strong_password(password):
        pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
        return re.match(pattern, password)
    # Registration route to handle user registration with email and hashed password
    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if request.method == 'POST':
            email = request.form['email']
            password = request.form['password']

            # Check if password is strong
            if not is_strong_password(password):
                flash("Password must be at least 8 characters long and include one uppercase letter, one lowercase letter, one number, and one special character.", "error")
                return redirect(url_for('register'))

            password_hash = generate_password_hash(password)  # Hash the password for secure storage

            if find_user_by_email(email):
                flash('Email is already registered.', 'error')
                return redirect(url_for('register'))

            insert_user(email, password_hash)  # Add user to the database

            session['email'] = email  # Log the user in after registration
            return redirect(url_for('set_file_password'))  # Redirect to file password setup
        return render_template('register_menu.html')
    # Login route to authenticate the user with email, password, and MFA
    @app.route('/login', methods=['GET', 'POST'])
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            email = request.form['email']
            password = request.form['password']
            otp = request.form.get('otp')  

            user = find_user_by_email(email)  

            # Ensure user exists and password is correct
            if user and check_password_hash(user['password_hash'], password):  
                if 'mfa_secret' in user and user['mfa_secret']:  
                    try:
                        decrypted_mfa_secret = decrypt_secret(user['mfa_secret'])

                        # Ensure MFA secret is decrypted correctly
                        if not decrypted_mfa_secret:
                            flash('Error retrieving MFA secret. Try again.', 'error')
                            return redirect(url_for('login'))

                        print(f"Decrypted MFA Secret: {decrypted_mfa_secret}")  

                        totp = pyotp.TOTP(decrypted_mfa_secret)

                        # Ensure OTP is provided and is correct
                        if not otp or not totp.verify(otp):  
                            flash('Invalid or missing OTP. Please try again.', 'error')
                            
                            # Log failed MFA attempt
                            add_log("WARNING", f"Failed MFA attempt for {email}: Incorrect OTP entered")

                            return redirect(url_for('login'))

                    except Exception as e:
                        flash(f"Error verifying MFA: {str(e)}", 'error')
                        return redirect(url_for('login'))

                # Save user session and redirect
                session['email'] = user['email']
                session['role'] = user['role']

                if user['role'] == 'admin':
                    return redirect(url_for('adminDashboard'))  
                else:
                    return redirect(url_for('userDashboard'))  

            else:
                flash('Invalid credentials.', 'error')

                # Log failed login due to incorrect password
                add_log("WARNING", f"Failed login attempt for {email}: Incorrect password")

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
