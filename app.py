import os
from flask import Flask, request, jsonify
from flask_migrate import Migrate
from models import db, User
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required

app = Flask(__name__)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

basePath = os.path.abspath(os.path.dirname(__file__))

class Config():
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basePath, 'data.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = "your_secret_key_here" 
    JWT_ALGORITHM = "HS256" 
    
    
app.config.from_object(Config)
db.init_app(app)


@app.route('/register', methods = ["POST"])
def register():
    User_data = request.get_json()
    if not User_data.get("Name") or not User_data.get("Email") or not User_data.get("Password") or not User_data.get("Age"):
        return jsonify({"Err":"Fill all the fields"}), 404
    
    
    if User.query.filter_by(Email = User_data.get("Email")).all():
        return jsonify({"Err":"User already exits"})
    
    
    
    
    hashed_password = bcrypt.generate_password_hash(User_data.get("Password")).decode('utf-8')
    print(hashed_password)
    new_user = User(Name = User_data.get("Name"), Email = User_data.get("Email"), Password = hashed_password, Age = User_data.get("Age"))
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({"Message":"User registered successfully"}), 201

@app.route('/login', methods = ["POST"])
def login():
    User_data = request.get_json()
    if  not User_data.get("Email") or not User_data.get("Password"):
        return jsonify({"Err":"Fill all the fields"}), 404
    user_details = User.query.filter_by(Email = User_data.get("Email")).first()
    print(user_details)
    if not user_details:
        return jsonify("User is not registered")
    if not bcrypt.check_password_hash(user_details.Password, User_data.get("Password")):
        return jsonify({"Err":"Invalid Password"}), 401
    token = create_access_token(identity = user_details.Email)
    print(token)
    return jsonify({
       "Message": "User Logged in successfully",
       "Token":token}), 200 
    
    
@app.route('/profile')
@jwt_required()
def profile():
    user_email = get_jwt_identity()
    print(user_email)
    user_details = User.query.filter_by(Email=user_email).first()
    if not user_details:
        return "user not found"
    print(user_details)
    
    return jsonify({
        "Name":user_details.Name,
        "Email":user_details.Email,
        "Age":user_details.Age
        
    }), 200
    
@app.route('/edit',methods = ["PUT"])
@jwt_required()
def edit():
    
    user_email = get_jwt_identity()
    user_details = User.query.filter_by(Email = user_email).first()
    if not user_details:
        return "User not found"
    updated_details = request.get_json()
    
    user_details.Name = updated_details["Name"]
    user_details.Age = updated_details["Age"]
    db.session.commit()
    return jsonify({
        "Message":"User details edited!",
        "Name": user_details.Name,
        "Email": user_email,
        "Age":user_details.Age
    })
    
    
@app.route('/delete', methods = ["DELETE"])
@jwt_required()
def delete():
    user_email =get_jwt_identity()
    user_details = User.query.filter_by(Email = user_email).first()
    if not user_details:
        return "User not found"
    db.session.delete(user_details)
    db.session.commit()
    return "User Details Deleted"
    
    

    
    

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)