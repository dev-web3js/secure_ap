from flask import Flask, jsonify, request
from flask_restful import Api, Resource, reqparse
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail
from utils.auth import auth_bp, UserRegistration, UserLogin, TwoFactorAuth
from utils.security import validate_input, encrypt_data, decrypt_data

app = Flask(__name__)
api = Api(app)
bcrypt = Bcrypt(app)

# Add the Flask-Mail configuration settings
app.config['MAIL_SERVER'] = 'smtp.mailtrap.io'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_mailtrap_username'  # Update this with your Mailtrap username
app.config['MAIL_PASSWORD'] = 'your_mailtrap_password'  # Update this with your Mailtrap password

# Enable debug mode for detailed error messages
app.config['DEBUG'] = True
app.config['PROPAGATE_EXCEPTIONS'] = True

jwt = JWTManager(app)
mail = Mail(app)  # Initialize Flask-Mail

# Initialize rate limiting
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# In-memory data store
users = []
products = []
orders = []
logs = []
reviews = []
carts = []

user_args = reqparse.RequestParser()
user_args.add_argument("name", type=str, required=True, help="Name of the user")
user_args.add_argument("age", type=int, required=True, help="Age of the user")
user_args.add_argument("occupation", type=str, required=True, help="Occupation of the user")
user_args.add_argument("role", type=str, required=True, help="Role of the user (customer/admin)")

product_args = reqparse.RequestParser()
product_args.add_argument("name", type=str, required=True, help="Name of the product")
product_args.add_argument("price", type=float, required=True, help="Price of the product")
product_args.add_argument("description", type=str, required=True, help="Description of the product")

order_args = reqparse.RequestParser()
order_args.add_argument("product_id", type=int, required=True, help="ID of the product to purchase")
order_args.add_argument("quantity", type=int, required=True, help="Quantity to purchase")

review_args = reqparse.RequestParser()
review_args.add_argument("product_id", type=int, required=True, help="ID of the product")
review_args.add_argument("rating", type=int, required=True, help="Rating of the product")
review_args.add_argument("review", type=str, required=True, help="Review of the product")

# Example route for user registration
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    # Your registration logic here
    return jsonify(message="User registered successfully"), 201

class UserResource(Resource):
    @jwt_required()
    def get(self, name):
        user = next((user for user in users if user["name"] == name), None)
        if user:
            return decrypt_data(user), 200
        return {"message": "User not found"}, 404

    @jwt_required()
    def post(self):
        args = user_args.parse_args()
        if any(user["name"] == args["name"] for user in users):
            return {"message": "User already exists"}, 400
        user = {
            "name": args["name"],
            "age": args["age"],
            "occupation": args["occupation"],
            "role": args["role"]
        }
        if not validate_input(user):
            return {"message": "Invalid input"}, 400
        users.append(encrypt_data(user))
        return user, 201

    @jwt_required()
    def put(self, name):
        args = user_args.parse_args()
        user = next((user for user in users if user["name"] == name), None)
        if user is None:
            user = {
                "name": name,
                "age": args["age"],
                "occupation": args["occupation"],
                "role": args["role"]
            }
            if not validate_input(user):
                return {"message": "Invalid input"}, 400
            users.append(encrypt_data(user))
            return user, 201
        else:
            user["age"] = args["age"]
            user["occupation"] = args["occupation"]
            user["role"] = args["role"]
            return decrypt_data(user), 200

    @jwt_required()
    def delete(self, name):
        global users
        users = [user for user in users if user["name"] != name]
        return {"message": "User deleted"}, 200

class ProductResource(Resource):
    @jwt_required()
    def get(self, product_id):
        product = next((product for product in products if product["id"] == product_id), None)
        if product:
            return product, 200
        return {"message": "Product not found"}, 404

    @jwt_required()
    def post(self):
        args = product_args.parse_args()
        product_id = len(products) + 1
        product = {
            "id": product_id,
            "name": args["name"],
            "price": args["price"],
            "description": args["description"]
        }
        products.append(product)
        return product, 201

    @jwt_required()
    def put(self, product_id):
        args = product_args.parse_args()
        product = next((product for product in products if product["id"] == product_id), None)
        if product is None:
            product = {
                "id": product_id,
                "name": args["name"],
                "price": args["price"],
                "description": args["description"]
            }
            products.append(product)
            return product, 201
        else:
            product["name"] = args["name"]
            product["price"] = args["price"]
            product["description"] = args["description"]
            return product, 200

    @jwt_required()
    def delete(self, product_id):
        global products
        products = [product for product in products if product["id"] != product_id]
        return {"message": "Product deleted"}, 200

class OrderResource(Resource):
    @jwt_required()
    def post(self):
        args = order_args.parse_args()
        product = next((product for product in products if product["id"] == args["product_id"]), None)
        if product is None:
            return {"message": "Product not found"}, 404
        order = {
            "user": get_jwt_identity(),
            "product_id": args["product_id"],
            "quantity": args["quantity"],
            "total_price": args["quantity"] * product["price"]
        }
        orders.append(order)
        return order, 201

    @jwt_required()
    def get(self):
        current_user = get_jwt_identity()
        user_orders = [order for order in orders if order["user"] == current_user]
        return user_orders, 200

class ReviewResource(Resource):
    @jwt_required()
    def post(self):
        args = review_args.parse_args()
        review = {
            "user": get_jwt_identity(),
            "product_id": args["product_id"],
            "rating": args["rating"],
            "review": args["review"]
        }
        reviews.append(review)
        return review, 201

    @jwt_required()
    def get(self, product_id):
        product_reviews = [review for review in reviews if review["product_id"] == product_id]
        return product_reviews, 200

class CartResource(Resource):
    @jwt_required()
    def post(self):
        args = order_args.parse_args()
        cart_item = {
            "user": get_jwt_identity(),
            "product_id": args["product_id"],
            "quantity": args["quantity"]
        }
        carts.append(cart_item)
        return cart_item, 201

    @jwt_required()
    def get(self):
        current_user = get_jwt_identity()
        user_cart = [item for item in carts if item["user"] == current_user]
        return user_cart, 200

    @jwt_required()
    def delete(self, product_id):
        current_user = get_jwt_identity()
        global carts
        carts = [item for item in carts if not (item["user"] == current_user and item["product_id"] == product_id)]
        return {"message": "Item removed from cart"}, 200

api.add_resource(UserRegistration, '/register')
api.add_resource(UserLogin, '/login')
api.add_resource(UserResource, "/user/<string:name>")
api.add_resource(ProductResource, "/product/<int:product_id>")
api.add_resource(OrderResource, "/order")
api.add_resource(ReviewResource, "/review/<int:product_id>")
api.add_resource(CartResource, "/cart/<int:product_id>")
api.add_resource(TwoFactorAuth, '/2fa')

app.register_blueprint(auth_bp)

if __name__ == '__main__':
    app.run(debug=True)
