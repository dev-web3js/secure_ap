from flask import Blueprint, request, jsonify
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from flask_mail import Mail, Message
from flask_restful import Resource  # Import Resource from flask_restful

auth_bp = Blueprint('auth', __name__)
bcrypt = Bcrypt()
mail = Mail()

users = []  # In-memory user storage for demonstration purposes


class UserRegistration(Resource):
    def post(self):
        data = request.get_json()
        hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        new_user = {'username': data['username'], 'password': hashed_password}
        users.append(new_user)  # Add user to the in-memory list
        return jsonify({"message": "User registered successfully"}), 201


class UserLogin(Resource):
    def post(self):
        data = request.get_json()
        user = next((u for u in users if u['username'] == data['username']), None)  # Retrieve user from the in-memory list
        if user and bcrypt.check_password_hash(user['password'], data['password']):
            access_token = create_access_token(identity=user['username'])
            return jsonify({"access_token": access_token}), 200
        return jsonify({"message": "Invalid credentials"}), 401


class TwoFactorAuth(Resource):
    @jwt_required()
    def post(self):
        data = request.get_json()
        otp = data['otp']
        user = get_jwt_identity()
        # Assuming a function otp_is_valid() that verifies the OTP
        if otp_is_valid(otp, user):
            return jsonify({"message": "2FA successful"}), 200
        return jsonify({"message": "Invalid OTP"}), 400


def otp_is_valid(otp, user):
    # Placeholder function for OTP validation logic
    return otp == "123456"  # For demonstration purposes, assume the correct OTP is "123456"
