from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash, abort, send_file
from database.mongo_db import db
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from bson.objectid import ObjectId
from google.cloud import storage
from datetime import datetime
from gcs_client import get_gcs_client, GCS_BUCKET_NAME
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
from io import BytesIO
import os, io

def file_routes(app):
    @app.route('/files', methods=['GET'], endpoint='files')
    def list_files():
        if 'email' not in session:
            flash('You need to log in to view your files.', 'error')
            return redirect(url_for('loginMenu'))

        user_email = session['email']
        # Convert the cursor to a list
        user_files = list(db.files.find({'email': user_email}))

        # Exclude hidden system files like .DS_Store
        visible_files = [file for file in user_files if not file['filename'].startswith('.')]

        return render_template('files.html', files=visible_files)

    @app.route('/set_file_password', methods=['GET', 'POST'])
    def set_file_password():
        if 'email' not in session:
            return redirect(url_for('loginMenu'))

        if request.method == 'POST':
            file_password = request.form['file_password']
            hashed_file_password = generate_password_hash(file_password)
            db.users.update_one({'email': session['email']}, {'$set': {'file_password': hashed_file_password}})
            return redirect(url_for('userDashboard'))
        return render_template('set_file_password.html')

    @app.route('/upload', methods=['GET', 'POST'])
    def upload_file():
        if 'email' not in session:
            return redirect(url_for('loginMenu'))

        if request.method == 'POST':
            user = db.users.find_one({'email': session['email']})
            if not user:
                flash('User not found. Please log in again.', 'error')
                return redirect(url_for('loginMenu'))

            file_password = request.form.get('file_password')
            if 'file_password' in user:
                if not check_password_hash(user['file_password'], file_password):
                    flash('Invalid file password.', 'error')
                    return redirect(url_for('upload_file'))
            else:
                flash('File password not set. Please set it first.', 'error')
                return redirect(url_for('set_file_password'))

            file = request.files['file']
            if file:
                user_email = session['email']
                filename = secure_filename(f"{user_email}_{file.filename}")

                # Encrypt file in-memory
                file_data = file.read()
                key = hashlib.sha256(file_password.encode()).digest()
                cipher = AES.new(key, AES.MODE_CBC)
                encrypted_data = cipher.iv + cipher.encrypt(pad(file_data, AES.block_size))

                # Upload encrypted data to GCS
                client = storage.Client()
                bucket = client.bucket(GCS_BUCKET_NAME)
                blob = bucket.blob(filename + ".enc")
                blob.upload_from_file(BytesIO(encrypted_data))

                # Save metadata in MongoDB
                db.files.insert_one({
                    'email': user_email,
                    'filename': filename + ".enc",
                    'upload_time': datetime.utcnow().isoformat()
                })

                flash('File uploaded and encrypted successfully!', 'success')
                return redirect(url_for('files'))

        return render_template('upload.html')

    @app.route('/download/<filename>', methods=['GET', 'POST'])
    def download_file(filename):
        if 'email' not in session:
            flash('You need to log in first.', 'error')
            return redirect(url_for('loginMenu'))

        user = db.users.find_one({'email': session['email']})
        if not user or 'file_password' not in user:
            flash('File password not set. Please set your file password first.', 'error')
            return redirect(url_for('set_file_password'))

        if request.method == 'GET':
            return render_template('enter_file_password.html', filename=filename)

        file_password = request.form.get('file_password')
        if not file_password:
            flash('File password is required.', 'error')
            return redirect(url_for('download_file', filename=filename))

        if not check_password_hash(user['file_password'], file_password):
            flash('Incorrect file password. Please try again.', 'error')
            return redirect(url_for('download_file', filename=filename))

        try:
            # Download encrypted file from GCS
            client = storage.Client()
            bucket = client.bucket(GCS_BUCKET_NAME)
            blob = bucket.blob(filename)
            encrypted_data = blob.download_as_bytes()

            # Decrypt the file
            key = hashlib.sha256(file_password.encode()).digest()
            iv = encrypted_data[:16]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_data = unpad(cipher.decrypt(encrypted_data[16:]), AES.block_size)

            # Serve the decrypted file
            return send_file(
                io.BytesIO(decrypted_data),
                mimetype='application/octet-stream',
                as_attachment=True,
                download_name=filename.replace('.enc', '')  # Original filename without .enc
            )
        except Exception as e:
            flash(f'Failed to download or decrypt the file: {str(e)}', 'error')
            return redirect(url_for('files'))

    @app.route('/view_decrypted_file/<filename>/<share_id>', methods=['POST'])
    def view_decrypted_file(filename, share_id):
        if 'email' not in session:
            return redirect(url_for('loginMenu'))
        
        file_password = request.form.get('file_password')
        user = db.users.find_one({'email': session['email']})
        
        if 'file_password' in user:
            if check_password_hash(user['file_password'], file_password):
                # Decrypt the file using the user's file password
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                decrypted_content = decrypt_and_get_content(file_path, file_password)
                
                if decrypted_content:
                    # Render a template to display the decrypted file content
                    return render_template('view_decrypted_content.html', content=decrypted_content, filename=filename, file_password=file_password, share_id=share_id)
                else:
                    # If decryption failed, inform the user
                    flash('Failed to decrypt the file. Please try again.', 'error')
                    return redirect(url_for('download_file', filename=filename))
            else:
                # If the provided file password is incorrect, inform the user and redirect back
                flash('Incorrect file password. Please try again.', 'error')
                return redirect(url_for('download_file', filename=filename))
        else:
            return "File password not set. Please set your file password first."

    @app.route('/received_files')
    def received_files():
        if 'email' not in session:
            flash('You need to log in to view your received files.', 'error')
            return redirect(url_for('loginMenu'))

        user_email = session['email']
        
        # Fetch all files shared with the current user
        shared_files = list(db.shared_files.find({'recipient_email': user_email}))

        return render_template('received_files.html', files=shared_files)

    @app.route('/share', methods=['GET', 'POST'])
    def share():
        if 'email' not in session:
            return redirect(url_for('loginMenu'))

        user_files = list(db.files.find({'email': session['email']}))

        if request.method == 'POST':
            recipient_email = request.form.get('recipient_email')
            filename = request.form.get('filename')

            recipient = db.users.find_one({'email': recipient_email})
            if not recipient:
                flash('Recipient not registered.', 'error')
                return render_template('share.html', user_files=user_files)

            # Insert shared file entry into DB
            db.shared_files.insert_one({
                'sender': session['email'],
                'recipient_email': recipient_email,
                'filename': filename,
                'shared_at': datetime.utcnow()
            })

            flash(f'File shared successfully with {recipient_email}.', 'success')
            return redirect(url_for('files'))

        return render_template('share.html', user_files=user_files)

    @app.route('/get_file/<filename>')
    def get_file(filename):
        if 'email' not in session:
            return redirect(url_for('loginMenu'))
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    
    @app.route('/download_shared_file/<shared_file_id>', methods=['GET', 'POST'])
    def download_shared_file(shared_file_id):
        if 'email' not in session:
            flash('You need to log in first.', 'error')
            return redirect(url_for('loginMenu'))

        shared_file = db.shared_files.find_one({'_id': ObjectId(shared_file_id)})
        if not shared_file:
            flash('Shared file not found.', 'error')
            return redirect(url_for('received_files'))

        filename = shared_file['filename']
        sender_email = shared_file['sender']
        recipient_email = session['email']

        sender = db.users.find_one({'email': sender_email})
        recipient = db.users.find_one({'email': recipient_email})

        if request.method == 'GET':
            return render_template('receivers_enter_file_password.html', filename=filename, shared_file_id=shared_file_id)

        file_password = request.form.get('file_password')
        if not file_password:
            flash('File password is required.', 'error')
            return redirect(url_for('download_shared_file', shared_file_id=shared_file_id))

        # Validate sender's file password for decryption
        if not sender or not check_password_hash(sender.get('file_password', ''), file_password):
            flash('Incorrect file password.', 'error')
            return redirect(url_for('download_shared_file', shared_file_id=shared_file_id))

        try:
            # Download encrypted file from GCS
            client = get_gcs_client()
            bucket = client.bucket(GCS_BUCKET_NAME)
            blob = bucket.blob(filename)
            encrypted_data = blob.download_as_bytes()

            # Ensure valid encrypted file length
            if len(encrypted_data) < 16:
                raise ValueError("File data too short for valid IV and content.")

            # Decrypt with sender's password
            sender_key = hashlib.sha256(file_password.encode()).digest()
            iv = encrypted_data[:16]
            cipher = AES.new(sender_key, AES.MODE_CBC, iv)
            decrypted_data = unpad(cipher.decrypt(encrypted_data[16:]), AES.block_size)

            # Serve decrypted file
            return send_file(
                io.BytesIO(decrypted_data),
                mimetype='application/octet-stream',
                as_attachment=True,
                download_name=filename.replace('.enc', '')  # Restore original filename
            )

        except ValueError as ve:
            flash(f"Decryption failed due to padding: {str(ve)}", 'error')
        except Exception as e:
            flash(f"Failed to download or decrypt the file: {str(e)}", 'error')

        return redirect(url_for('received_files'))
    
    @app.route('/delete_received_file/<file_id>', methods=['POST'])
    def delete_received_file(file_id):
        if 'email' in session:
            user_email = session['email']
            
            # Ensure the file to be deleted was shared with the logged-in user
            db.shared_files.delete_one({'_id': ObjectId(file_id), 'recipient_email': user_email})
            
            flash('Received file deleted successfully!', 'success')
            return redirect(url_for('received_files'))
        else:
            flash('Unauthorized action!', 'error')
            return redirect(url_for('loginMenu'))
    
    @app.route('/manage_files')
    def manage_files():
        if 'role' in session and session['role'] == 'admin':
            # Fetch files from GCS bucket
            client = get_gcs_client()
            bucket = client.bucket(GCS_BUCKET_NAME)
            
            blobs = bucket.list_blobs()  # List all files in the bucket
            
            # Show all files, including encrypted and non-encrypted versions
            gcs_files = []
            for blob in blobs:
                gcs_files.append({
                    'filename': blob.name,
                    'size': blob.size,
                    'last_modified': blob.updated,
                })
            
            # Fetch encrypted file metadata from MongoDB for comparison
            db_files = list(db.files.find())

            return render_template(
                'encrypted_files.html',
                gcs_files=gcs_files,
                db_files=db_files
            )
        else:
            flash('Unauthorized action!', 'error')
            return redirect(url_for('loginMenu'))
        
    @app.route('/delete_file/<filename>', methods=['POST'])
    def delete_file(filename):
        if 'email' in session:
            # Initialize GCS client
            client = get_gcs_client()
            bucket = client.bucket(GCS_BUCKET_NAME)
            blob = bucket.blob(filename)
            
            # Delete the file from GCS
            blob.delete()
            
            # Optionally delete file metadata from MongoDB
            db.files.delete_one({'filename': filename, 'email': session['email']})
            
            flash(f'File {filename} deleted successfully from GCS!', 'success')
            return redirect(url_for('manage_files'))
        else:
            flash('Unauthorized action!', 'error')
            return redirect(url_for('loginMenu'))