from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash, abort, send_file
from database.mongo_db import db # MongoDB database instance for storing metadata and shared files
from werkzeug.security import generate_password_hash, check_password_hash # Password hashing and verification
from werkzeug.utils import secure_filename # For securing uploaded filenames
from bson.objectid import ObjectId # To work with MongoDB ObjectIds
from google.cloud import storage # To interact with Google Cloud Storage
from datetime import datetime # For timestamping file uploads and shared files
from gcs_client import get_gcs_client, GCS_BUCKET_NAME # Utility functions and constants for Google Cloud Storage integration
from Crypto.Cipher import AES # For AES encryption and decryption
from Crypto.Util.Padding import pad, unpad # For padding/unpadding data for AES encryption
import hashlib # To generate secure keys using SHA-256
from database.mongo_db import add_log
from io import BytesIO # For working with file-like objects in memory
import os, io, re  # Standard Python modules for file and path handling

def file_routes(app):
    # Route for listing files belonging to the logged-in user
    @app.route('/files', methods=['GET'], endpoint='files')
    def list_files():
        if 'email' not in session:
            flash('You need to log in to view your files.', 'error')
            return redirect(url_for('login'))

        user_email = session['email']
        # Fetch all files belonging to the user from the MongoDB files collection
        user_files = list(db.files.find({'email': user_email}))

        
        visible_files = [file for file in user_files if not file['filename'].startswith('.')]

        return render_template('files.html', files=visible_files)
    # Function to validate a strong file password
    def is_strong_password(password):
        pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
        return re.match(pattern, password)
    # Route for setting a file password (additional security for file encryption)
    @app.route('/set_file_password', methods=['GET', 'POST'])
    def set_file_password():
        if 'email' not in session:
            return redirect(url_for('login'))

        if request.method == 'POST':
            file_password = request.form['file_password']

            # Validate file password
            if not is_strong_password(file_password):
                flash("File password must be at least 8 characters long and include one uppercase letter, one lowercase letter, one number, and one special character.", "error")
                return redirect(url_for('set_file_password'))

            hashed_file_password = generate_password_hash(file_password)  # Hash the password
            db.users.update_one({'email': session['email']}, {'$set': {'file_password': hashed_file_password}})
            
            flash('Passwords set successfully!', 'success')
            return redirect(url_for('userDashboard'))

        return render_template('set_file_password.html')
    # Route for uploading a file
    @app.route('/upload', methods=['GET', 'POST'])
    def upload_file():
        if 'email' not in session:
            return redirect(url_for('login'))
        
        if request.method == 'POST':
            # Retrieve the user's information from the database
            user = db.users.find_one({'email': session['email']})
            if not user:
                flash('User not found. Please log in again.', 'error')
                return redirect(url_for('login'))
            # Retrieve the file password entered by the user
            file_password = request.form.get('file_password')
            # Verify the file password if it's set
            if 'file_password' in user:
                if not check_password_hash(user['file_password'], file_password):
                    flash('Invalid file password.', 'error')

                    # Log incorrect file password attempt during upload
                    add_log("WARNING", f"User {session['email']} entered incorrect file password during upload")

                    return redirect(url_for('upload_file'))
            else:
                flash('File password not set. Please set it first.', 'error')
                return redirect(url_for('set_file_password'))
            # Retrieve the uploaded file
            file = request.files['file']
            if file:
                # Generate a secure filename using the user's email and the original filename
                user_email = session['email']
                filename = secure_filename(f"{user_email}_{file.filename}")

                # Read the file data and encrypt it using AES
                file_data = file.read()
                file_size = len(file_data)
                ip = request.remote_addr
                key = hashlib.sha256(file_password.encode()).digest()
                cipher = AES.new(key, AES.MODE_CBC)
                encrypted_data = cipher.iv + cipher.encrypt(pad(file_data, AES.block_size))

                print(f"Encryption Key (Upload): {key.hex()}")
                print(f"IV during encryption: {cipher.iv.hex()}")
                print(f"Encrypted data length: {len(encrypted_data)} bytes")
                # Upload the encrypted file to Google Cloud Storage
                client = storage.Client()
                bucket = client.bucket(GCS_BUCKET_NAME)
                blob = bucket.blob(filename + ".enc")
                blob.upload_from_file(BytesIO(encrypted_data))

                 # Insert file metadata into the MongoDB 'files' collection
                db.files.insert_one({
                    'email': user_email,
                    'filename': filename + ".enc",
                    'upload_time': datetime.utcnow().isoformat()
                })

                # Log the file upload
                add_log("INFO", f"User {session['email']} uploaded file: {filename}", ip=ip)

                flash('File uploaded and encrypted successfully!', 'success')
                return redirect(url_for('files'))

        return render_template('upload.html')
    # Route for downloading and decrypting a file
    @app.route('/download/<filename>', methods=['GET', 'POST'])
    def download_file(filename):
        if 'email' not in session:
            flash('You need to log in first.', 'error')
            return redirect(url_for('login'))
        # Retrieve the user's information from the database
        user = db.users.find_one({'email': session['email']})
        if not user or 'file_password' not in user:
            flash('File password not set. Please set your file password first.', 'error')
            return redirect(url_for('set_file_password'))
        # Handle GET request to display the password input form
        if request.method == 'GET':
            return render_template('enter_file_password.html', filename=filename)
        # Handle POST request to download the file
        file_password = request.form.get('file_password')
        if not file_password:
            flash('File password is required.', 'error')
            return redirect(url_for('download_file', filename=filename))

        if not check_password_hash(user['file_password'], file_password):
            flash('Incorrect file password. Please try again.', 'error')

            # Log incorrect file password attempt during download
            add_log("WARNING", f"User {session['email']} entered incorrect file password for {filename} during download")

            return redirect(url_for('download_file', filename=filename))

        try:
            # Download the encrypted file from Google Cloud Storage
            client = storage.Client()
            bucket = client.bucket(GCS_BUCKET_NAME)
            blob = bucket.blob(filename)
            encrypted_data = blob.download_as_bytes()
            file_size = len(encrypted_data)
            ip = request.remote_addr

            # Decrypt the file data using AES
            key = hashlib.sha256(file_password.encode()).digest()
            iv = encrypted_data[:16] # Extract the initialization vector (IV)
            cipher = AES.new(key, AES.MODE_CBC, iv) 
            decrypted_data = unpad(cipher.decrypt(encrypted_data[16:]), AES.block_size)
	    # After extracting IV and setting up cipher:
            print(f"Decryption Key (Download): {key.hex()}")
            print(f"IV during decryption: {iv.hex()}")
            print(f"Encrypted data length: {len(encrypted_data)} bytes")
            # Log successful file download
            add_log("INFO", f"User {session['email']} downloaded file: {filename}", ip=ip)

            # Send the decrypted file to the user for download
            return send_file(
                io.BytesIO(decrypted_data),
                mimetype='application/octet-stream',
                as_attachment=True,
                download_name=filename.replace('.enc', '')  
            )
        except Exception as e:
            flash(f'Failed to download or decrypt the file: {str(e)}', 'error')
            return redirect(url_for('files'))
    # Route for viewing a decrypted file's content
    @app.route('/view_decrypted_file/<filename>/<share_id>', methods=['POST'])
    def view_decrypted_file(filename, share_id):
        if 'email' not in session:
            return redirect(url_for('login'))
        # Retrieve the file password entered by the user
        file_password = request.form.get('file_password')
        # Find the user's data in the database
        user = db.users.find_one({'email': session['email']})
        
        if 'file_password' in user:
            if check_password_hash(user['file_password'], file_password):
                # Construct the file path in the local upload folder
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                # Attempt to decrypt and retrieve the content
                decrypted_content = decrypt_and_get_content(file_path, file_password)
                # If decryption succeeds, render the content for the user
                if decrypted_content:
                    
                    return render_template('view_decrypted_content.html', content=decrypted_content, filename=filename, file_password=file_password, share_id=share_id)
                else:
                    
                    flash('Failed to decrypt the file. Please try again.', 'error')
                    return redirect(url_for('download_file', filename=filename))
            else:
                
                flash('Incorrect file password. Please try again.', 'error')
                return redirect(url_for('download_file', filename=filename))
        else:
            return "File password not set. Please set your file password first."
    # Route for listing files shared with the logged-in user
    @app.route('/received_files')
    def received_files():
        if 'email' not in session:
            flash('You need to log in to view your received files.', 'error')
            return redirect(url_for('login'))
        # Get the logged-in user's email
        user_email = session['email']
        
        # Fetch all files shared with the user from the shared_files collection
        shared_files = list(db.shared_files.find({'recipient_email': user_email}))

        return render_template('received_files.html', files=shared_files)
    # Route for sharing a file with another user
    @app.route('/share', methods=['GET', 'POST'])
    def share():
        if 'email' not in session:
            return redirect(url_for('login'))

        user_files = list(db.files.find({'email': session['email']}))

        if request.method == 'POST':
            recipient_email = request.form.get('recipient_email')
            filename = request.form.get('filename')

            recipient = db.users.find_one({'email': recipient_email})
            sender = db.users.find_one({'email': session['email']})

            if not recipient:
                flash('Recipient not registered.', 'error')
                return render_template('share.html', user_files=user_files)

            if 'file_password' not in sender or 'file_password' not in recipient:
                flash('Both sender and recipient must have file passwords set.', 'error')
                return redirect(url_for('share'))

            sender_password = request.form.get('file_password')
            if not sender_password:
                flash('Sender file password is required.', 'error')
                return redirect(url_for('share'))

            if not check_password_hash(sender['file_password'], sender_password):
                flash('Incorrect sender password.', 'error')

                # Log incorrect file password attempt during sharing
                add_log("WARNING", f"User {session['email']} entered incorrect file password while sharing {filename}")


                return redirect(url_for('share'))

            try:
                # Retrieve recipient's hashed password
                recipient_password_hash = recipient['file_password']

                # Download encrypted file from Google Cloud Storage
                client = get_gcs_client()
                bucket = client.bucket(GCS_BUCKET_NAME)
                blob = bucket.blob(filename)
                encrypted_data = blob.download_as_bytes()

                # Decrypt using sender's key
                sender_key = hashlib.sha256(sender_password.encode()).digest()
                iv = encrypted_data[:16]  # Extract IV
                cipher = AES.new(sender_key, AES.MODE_CBC, iv)
                decrypted_data = unpad(cipher.decrypt(encrypted_data[16:]), AES.block_size)

                # Re-encrypt using recipient's password-derived key
                new_iv = os.urandom(16)  
                recipient_key = hashlib.sha256(recipient_password_hash.encode()).digest()  
                new_cipher = AES.new(recipient_key, AES.MODE_CBC, new_iv)
                new_encrypted_data = new_iv + new_cipher.encrypt(pad(decrypted_data, AES.block_size))

                # Save the new encrypted file
                new_filename = f"shared_{filename}"
                new_blob = bucket.blob(new_filename)
                new_blob.upload_from_string(new_encrypted_data)
                ip = request.remote_addr
                file_size = len(new_encrypted_data)

                print(f"Sender key: {sender_key.hex()}")
                print(f"Recipient key (Encryption): {recipient_key.hex()}")
                print(f"IV during encryption: {new_iv.hex()}")

                # Store sharing info in DB
                db.shared_files.insert_one({
                    'sender': session['email'],
                    'recipient_email': recipient_email,
                    'filename': new_filename,
                    'shared_at': datetime.utcnow(),
                    'iv': new_iv.hex()  
                })

                # Log file sharing
                add_log("INFO", f"User {session['email']} shared file: {filename} with {recipient_email}", ip=ip)


                flash(f'File shared successfully with {recipient_email}.', 'success')
                return redirect(url_for('files'))

            except Exception as e:
                flash(f'Error sharing file: {str(e)}', 'error')
                return redirect(url_for('share'))

        return render_template('share.html', user_files=user_files)
    # Route for serving a file directly from the upload folder
    @app.route('/get_file/<filename>')
    def get_file(filename):
        if 'email' not in session:
            return redirect(url_for('login'))
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    # Route for downloading and decrypting a shared file
    @app.route('/download_shared_file/<shared_file_id>', methods=['GET', 'POST'])
    def download_shared_file(shared_file_id):
        if 'email' not in session:
            flash('You need to log in first.', 'error')
            return redirect(url_for('login'))

        shared_file = db.shared_files.find_one({'_id': ObjectId(shared_file_id)})
        if not shared_file:
            flash('Shared file not found.', 'error')
            return redirect(url_for('received_files'))

        filename = shared_file['filename']
        recipient_email = session['email']
        recipient = db.users.find_one({'email': recipient_email})

        if request.method == 'GET':
            return render_template('receivers_enter_file_password.html', filename=filename, shared_file_id=shared_file_id)

        file_password = request.form.get('file_password')
        if not file_password:
            flash('File password is required.', 'error')
            return redirect(url_for('download_shared_file', shared_file_id=shared_file_id))

        if not check_password_hash(recipient['file_password'], file_password):
            flash('Incorrect file password.', 'error')

            # Log incorrect file password attempt for shared file
            add_log("WARNING", f"User {session['email']} entered incorrect file password for shared file: {filename}")


            return redirect(url_for('download_shared_file', shared_file_id=shared_file_id))

        try:
            # Retrieve IV from DB
            iv = bytes.fromhex(shared_file['iv'])

            # Generate decryption key using recipient's stored hashed password
            recipient_key = hashlib.sha256(recipient['file_password'].encode()).digest()

            # Download encrypted file
            client = get_gcs_client()
            bucket = client.bucket(GCS_BUCKET_NAME)
            blob = bucket.blob(filename)
            encrypted_data = blob.download_as_bytes()
            file_size = len(encrypted_data)
            ip = request.remote_addr

            # Decrypt the file
            cipher = AES.new(recipient_key, AES.MODE_CBC, iv)

            # Debugging print statements
            print(f"Recipient key (Decryption): {recipient_key.hex()}")
            print(f"IV during decryption: {iv.hex()}")
            print(f"Encrypted data length: {len(encrypted_data)} bytes")

            decrypted_data = unpad(cipher.decrypt(encrypted_data[16:]), AES.block_size)

            # Log successful shared file download
            add_log("INFO", f"User {session['email']} downloaded shared file: {filename}", ip=ip)

            return send_file(
                io.BytesIO(decrypted_data),
                mimetype='application/octet-stream',
                as_attachment=True,
                download_name=filename.replace('.enc', '')
            )

        except ValueError as ve:
            print(f"Padding error during decryption: {ve}")
            flash(f"Decryption failed due to padding: {str(ve)}", 'error')
        except Exception as e:
            print(f"General decryption error: {e}")
            flash(f"Failed to download or decrypt the file: {str(e)}", 'error')

        return redirect(url_for('received_files'))
    # Route for deleting a received shared file
    @app.route('/delete_received_file/<file_id>', methods=['POST'])
    def delete_received_file(file_id):
        if 'email' in session:
            user_email = session['email']
            
            db.shared_files.delete_one({'_id': ObjectId(file_id), 'recipient_email': user_email})
            
            # Log the deletion of a received shared file
            ip = request.remote_addr
            add_log("INFO", f"User {session['email']} deleted received file: {file_id}", ip=ip)

            flash('Received file deleted successfully!', 'success')
            return redirect(url_for('received_files'))
        else:
            flash('Unauthorized action!', 'error')
            return redirect(url_for('login'))
    # Admin route for managing files in the system
    @app.route('/manage_files')
    def manage_files():
        if 'role' in session and session['role'] == 'admin':
            
            client = get_gcs_client()
            bucket = client.bucket(GCS_BUCKET_NAME)
            # List all blobs (files) in the bucket
            blobs = bucket.list_blobs()  
            
            # Collect metadata about each file in the bucket
            gcs_files = []
            for blob in blobs:
                gcs_files.append({
                    'filename': blob.name,
                    'size': blob.size,
                    'last_modified': blob.updated,
                })
            
            # Fetch all files metadata from MongoDB
            db_files = list(db.files.find())
            # Render the 'encrypted_files.html' template with GCS and database files
            return render_template(
                'encrypted_files.html',
                gcs_files=gcs_files,
                db_files=db_files
            )
        else:
            flash('Unauthorized action!', 'error')
            return redirect(url_for('login'))
    # Admin route for deleting files
    @app.route('/delete_file/<filename>', methods=['POST'])
    def delete_file(filename):
        # Ensure the user is logged in
        if 'email' in session:
            try:
                # Delete the file from Google Cloud Storage
                client = get_gcs_client()
                bucket = client.bucket(GCS_BUCKET_NAME)
                blob = bucket.blob(filename)
                
                
                blob.delete()

                ip = request.remote_addr
                file_size = blob.size if blob and blob.size else 0
                # Remove the file metadata from MongoDB
                db.files.delete_one({'filename': filename})  

                # Log the deletion of an uploaded file
                add_log("INFO", f"User {session['email']} deleted file: {filename}", ip=ip)

                flash(f'File {filename} deleted successfully from GCS and database!', 'success')
            except Exception as e:
                flash(f'An error occurred while deleting the file: {str(e)}', 'error')

            return redirect(url_for('files'))
        else:
            flash('Unauthorized action!', 'error')
            return redirect(url_for('login'))
