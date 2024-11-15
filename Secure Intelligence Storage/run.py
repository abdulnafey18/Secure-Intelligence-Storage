from flask import Flask
from routes.auth_routes import auth_routes
from routes.file_routes import file_routes
from routes.page_routes import page_routes
import os

app = Flask(__name__, static_folder='static')
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'Secure Intelligence Storage', 'uploads')
app.secret_key = 'your_secret_key'

# Register the routes
auth_routes(app)
file_routes(app)
page_routes(app)

if __name__ == '__main__':
    app.run(debug=True, port=5001)