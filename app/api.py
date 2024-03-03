from flask import Flask,request,jsonify
from flask_jwt_extended import create_access_token, jwt_required,get_jwt_identity
from werkzeug.security import generate_password_hash,check_password_hash
from .config import app, db,limiter 
from .models import User
import bleach
#=======================================================#
#handling the Requests OF GET POST PUT DELETE
#=======================================================#
#First endpoint method for creating a user 
@app.route('/api/create/user',methods=['POST'])
@limiter.limit("50 per hour") 
def create_user():
    #create JSON data from the request
    data = request.get_json()
    #generate user and password and bleach th request avoid SQL injection
    username = bleach.clean(data['username'])
    password_hash = generate_password_hash(bleach.clean(data['password']))
    exiting_user = User.query.filter_by(username=username).first()#or none
    #check if user name is exist
    if exiting_user:
        return jsonify({'message':'Username already exists'}),403 
    #if not create one
    new_user = User(username=username, password=password_hash,admin=False)
    try:
        #commit the request to postgresql    
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message':'Your user has been created successfully'}),201
    #handling server side error
    except IndexError as e:
        #undo the input
        db.session.rollback()
        return jsonify({'error': 'User creation failed. An unexpected error occurred.'}), 500
#==============================================================================#
#second endpoint login method to get data 
@app.route('/api/login',methods=['POST'])
@limiter.limit("50 per hour") 
def login():
    #sending auth Request to get token
    auth = request.authorization
    #here i check if its not empty and if not user or password
    if not auth or not auth.username or not auth.password:
        return jsonify({'message':'Invalid  credentials'}),401
    #take auth user 
    username = auth.username
    password = auth.password
    #check if user in user data
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password,password):
        #set the token for user id
        token = create_access_token(identity=user.id)
        #return token
        return jsonify({"message":"Your access token",'token':token}),200
    else:
        return jsonify({'message':'Invalid  credentials'}),401
#==============================================================================#
#third endpoint method to get a specific user with id
@app.route('/api/user/<id>',methods=['GET'])
@limiter.limit("50 per hour") 
@jwt_required() 
def get_user(id):
    #filter user from database by id
    user = User.query.filter_by(id=id).first()
    current_user_id = get_jwt_identity()
    #get identity by token 
    current_user = User.query.get(current_user_id)
    # if token of this user is not expired and user is admin 
    if current_user.admin:
        #if the id not found
        if not user:
            return jsonify({'message':'no user found'}),404
        else:
            user_data ={
                'id':user.id,
                'username':user.username,
                'password':user.password,
                'admin':user.admin
            } 
            return jsonify({'message':user_data}),200
    else:
        return jsonify({'message':'You dont have privileges to access'}),401
#==============================================================================#
#Get JWT token for login at get all data
@app.route('/api/users',methods=['GET'])
@limiter.limit("50 per hour") 
@jwt_required() 
def get_users():
    try:
        #get user token
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)
        #check if user is admin or no if admin give him all data
        if current_user.admin:
            users = User.query.all()
            #create dictionary
            data = []
            #get all users in dictionary    
            for user in users:
                user_data={
                    'id':user.id,
                    'username':user.username,
                    'password':user.password,
                    'admin':user.admin
                }
                data.append(user_data)
                # return all users data
            return jsonify({'users': data}), 200 
        else:
            return jsonify({'message':'You dont have privileges to access'}),401
    except Exception as e:
        #handling server error
        return jsonify({'error': 'An unexpected error occurred'}), 500
#==============================================================================#
#forth method edit user 
@app.route('/api/edit/user/<id>',methods=['PUT'])
@limiter.limit("50 per hour") 
@jwt_required()
def edit_data(id):
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    if current_user.admin:
        #get user id
        user = User.query.filter_by(id=id).first()
        #if user id not exist 
        if not user:
            return jsonify({'message':'No user found'}),404
        #if exist promote to admin
        try:
            user.admin = True
            db.session.commit()
            return jsonify ({'message':'Your data has been update'}),200
        #handling server error
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': 'An unexpected error occurred'}), 500
    else:
        return jsonify({'message':'You dont have privileges to access'}),401
#==============================================================================#
#fifth method Delete user
@app.route('/api/delete/user/<id>',methods=['DELETE'])
@limiter.limit("50 per hour") 
@jwt_required()
def delete_user(id):
    Current_user_id = get_jwt_identity()
    current_user = User.query.get(Current_user_id)
    if current_user.admin:
        user = User.query.filter_by(id=id).first()
        if not user:
            return jsonify({'message':'User not found'}),404
        else:
            db.session.delete(user)
            db.session.commit()
            return jsonify ({'message':'User has been deleted succsufly'}),200
    else:
        return jsonify({'message':'You dont have privileges to access'}),401
