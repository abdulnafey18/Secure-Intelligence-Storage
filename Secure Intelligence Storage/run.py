from flask import Flask  # Import Flask for creating the web application
from flask_talisman import Talisman  # Import Flask-Talisman to implement security headers
from routes.admin_routes import admin_routes
from routes.auth_routes import auth_routes  # Import authentication-related routes
from routes.file_routes import file_routes  # Import file-related routes
from routes.page_routes import page_routes  # Import page-related routes
import os  # Import the module to work with environment variables

# Initialize Flask application
app = Flask(__name__, static_folder='static')
# Configure the folder where uploaded files will be stored
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'Secure Intelligence Storage', 'uploads')
# Set the secret key for session management and CSRF protection
app.secret_key = 'your_secret_key'

# Define the Content Security Policy to control the resources the application can load
csp = {
    'default-src': ["'self'"],  
    'script-src': ["'self'"],  
    'style-src': ["'self'"], 
    'font-src': ["'self'"],  
    'img-src': ["'self'"],  
}

# Adding security headers to the Flask application using Talisman
# These headers prevent common web application vulnerabilities
Talisman(
    app,
    content_security_policy=csp,
    strict_transport_security=True,  # Enforce HSTS
    strict_transport_security_max_age=31536000,  # 1 year
    strict_transport_security_include_subdomains=True,  # Include subdomains
    strict_transport_security_preload=True,  # Allow preload
)

# Registering the routes
admin_routes(app)
auth_routes(app)
file_routes(app)
page_routes(app)

# Running the flask project
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)