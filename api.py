# api.py
from flask import Flask, request, jsonify, send_from_directory
import os
import backend
from werkzeug.utils import secure_filename
import traceback
import logging

app = Flask(__name__)
UPLOAD_FOLDER = "static/profile_pic"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


@app.route("/")
def frontend():
    return send_from_directory(
        os.path.dirname(os.path.abspath(__file__)), "frontend.html"
    )


@app.route("/register", methods=["POST"])
def register():
    name = request.form.get("name")
    mobile = request.form.get("mobile")
    password = request.form.get("password")
    profile_pic = None
    if "profile_pic" in request.files and request.files["profile_pic"].filename:
        file = request.files["profile_pic"]
        # file.filename can be Optional[str] according to type checkers; ensure it's a str
        filename = secure_filename(str(file.filename))
        file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
        profile_pic = filename  # store filename only
    return jsonify(backend.create_user(name, mobile, password, profile_pic))


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    return jsonify(backend.verify_user(data.get("mobile"), data.get("password")))


logging.basicConfig(level=logging.INFO)


@app.route("/fetch_users", methods=["POST"])
def api_fetch_users():
    try:
        data = request.get_json(force=True, silent=True) or {}
        current_user_id = data.get("current_user_id")
        if not current_user_id:
            return jsonify({"status": "error", "message": "Missing user ID"}), 400

        # allow user id strings; try convert to int for safety
        try:
            current_user_id = int(current_user_id)
        except Exception:
            return jsonify({"status": "error", "message": "Invalid user ID"}), 400

        result = backend.fetch_users(current_user_id)
        return jsonify(result)
    except Exception as e:
        logging.error("Exception in /fetch_users: %s\n%s", e, traceback.format_exc())
        # return JSON with message and avoid sending HTML stacktrace page
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "Server error in fetch_users",
                    "detail": str(e),
                }
            ),
            500,
        )


@app.route("/send_message", methods=["POST"])
def send_message():
    data = request.get_json() or {}
    if not all(k in data for k in ("sender_id", "receiver_id", "message")):
        return jsonify({"status": "error", "message": "Missing fields"})
    return jsonify(
        backend.store_message(data["sender_id"], data["receiver_id"], data["message"])
    )


@app.route("/fetch_messages", methods=["POST"])
def fetch_messages():
    data = request.get_json() or {}
    if not all(k in data for k in ("sender_id", "receiver_id")):
        return jsonify({"status": "error", "message": "Missing fields"})
    return jsonify(backend.fetch_messages(data["sender_id"], data["receiver_id"]))


@app.route("/monitor_messages", methods=["GET"])
def monitor_messages():
    return jsonify(backend.fetch_all_messages_monitor())


@app.route("/static/profile_pic/<filename>")
def profile_pic(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


if __name__ == "__main__":
    app.run(debug=True)
