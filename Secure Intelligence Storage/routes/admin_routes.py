from flask import jsonify
from database.mongo_db import db  # Import MongoDB connection

def admin_routes(app):
    @app.route('/get_logs/<log_type>', methods=['GET'])
    def get_logs(log_type):
        logs = list(db.logs.find({"type": log_type}, {"_id": 0}))  # Fetch logs of selected type
        return jsonify(logs)