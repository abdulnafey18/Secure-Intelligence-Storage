from flask import render_template, request, redirect, url_for, session, flash, send_file
from database.mongo_db import db
from werkzeug.security import generate_password_hash, check_password_hash
from database.mongo_db import db
from bson.objectid import ObjectId
import pyotp, qrcode
from io import BytesIO

def auth_routes(app):

    @app.route('/enable_mfa')
    def enable_mfa():
        if 'email' not in session:
            flash('Please log in first.', 'error')
            return redirect(url_for('loginMenu'))

        # Generate a new TOTP secret for the user
        secret = pyotp.random_base32()

        # Save the secret in the database for the logged-in user
        db.users.update_one({'email': session['email']}, {'$set': {'mfa_secret': secret}})

        # Generate the OTP provisioning URI
        otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(session['email'], issuer_name="Secure Intelligence Storage")

        # Generate a QR code for the OTP URI
        qr = qrcode.make(otp_uri)
        buf = BytesIO()
        qr.save(buf)
        buf.seek(0)

        return send_file(buf, mimetype='image/png', as_attachment=False)

    @app.route('/registerMenu', methods=['GET', 'POST'])
    def registerMenu():
        if request.method == 'POST':
            email = request.form['email']
            password = request.form['password']
            hashed_password = generate_password_hash(password)
            db.users.insert_one({'email': email, 'password': hashed_password, 'role': 'user'})
            session['email'] = email  # Store name in session for future steps
            return redirect(url_for('set_file_password'))
        return render_template('register_menu.html')

    @app.route('/loginMenu', methods=['GET', 'POST'])
    def loginMenu():
        if request.method == 'POST':
            email = request.form['email']
            password = request.form['password']
            otp = request.form.get('otp')
            user = db.users.find_one({'email': email})
            
            if user and check_password_hash(user['password'], password):
                if 'mfa_secret' in user:
                    totp = pyotp.TOTP(user['mfa_secret'])
                    if not otp or not totp.verify(otp):
                        flash('Invalid or missing OTP. Please try again.', 'error')
                        return redirect(url_for('loginMenu'))

                session['email'] = email
                session['role'] = user['role']  # Store the user's role in the session
                
                # Redirect based on role
                if user['role'] == 'admin':
                    return redirect(url_for('adminDashboard'))
                else:
                    return redirect(url_for('userDashboard'))
            else:
                flash('Invalid email or password.', 'error')
                return redirect(url_for('loginMenu'))
        
        return render_template('login_menu.html')

    @app.route('/logout')
    def logout():
        session.pop('email', None)
        return redirect(url_for('homepage'))
    
    @app.route('/delete_user/<user_id>', methods=['POST'])
    def delete_user(user_id):
        if 'role' in session and session['role'] == 'admin':
            db.users.delete_one({'_id': ObjectId(user_id)})  # Delete the user by ID
            flash('User deleted successfully!', 'success')
            return redirect(url_for('all_users'))
        else:
            flash('Unauthorized action!', 'error')
            return redirect(url_for('loginMenu'))