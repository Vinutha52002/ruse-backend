import json
import random
import certifi
# import awsgi 
# from serverless_wsgi import handle_request
from pymongo.errors import PyMongoError
import traceback
from flask import Flask, request, jsonify,send_from_directory
from flask_bcrypt import Bcrypt


from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity,
    JWTManager
)
from pymongo import MongoClient
import datetime
from datetime import timedelta 

import os

from dotenv import load_dotenv


from flask_cors import CORS
import re  
from bson import ObjectId 
load_dotenv()


DB_AUTH = 'Authentication'
DB_HOMES = 'homes_db'
DB_HOUSEHELP = 'househelp_db'
DB_GROCERIES = 'Groceries'
DB_ELECTRICITY = 'Electricity'
DB_GAS = 'Gas'
DB_WATER = 'Water'

DB_WARRANTIES = 'WARRANTIES'  #need to deploye
DB_NEWSPAPER = 'NEWSPAPER'

COL_USERS = 'users'
COL_HOMES = 'homes'
COL_HOUSEHELPS = 'househelps'
COL_CATEGORIES = 'categories'
COL_GROCERIES = 'groceries_list'
COL_GROC_REQ = 'groceries_out_of_stock'
COL_GROC_CAT ='groceries_categories'
COL_ENERGY = 'energy_consumption'
COL_GAS = 'gas_consumption'
COL_WATER = 'water_consumption'

COL_WARRANTIES = 'warranties'
COL_NEWSPAPER = 'newspaper_data'


app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET')
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = datetime.timedelta(hours=2)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = datetime.timedelta(days=7)
jwt = JWTManager(app)
CORS(app)
client = MongoClient(os.getenv('DB_URL'),tlsCAFile=certifi.where())


db_auth = client[DB_AUTH]
db_homes = client[DB_HOMES]
db_househelp = client[DB_HOUSEHELP]
db_groceries = client[DB_GROCERIES]
db_energy = client[DB_ELECTRICITY]
db_gas = client[DB_GAS]
db_water = client[DB_WATER]

db_warranties = client[DB_WARRANTIES]
db_newspaper = client[DB_NEWSPAPER]


users = db_auth[COL_USERS]
homes_collection = db_homes[COL_HOMES]
househelps_collection = db_househelp[COL_HOUSEHELPS]
categories_collection = db_househelp[COL_CATEGORIES]
groceries = db_groceries[COL_GROCERIES]
groceries_requests = db_groceries[COL_GROC_REQ]
categories = db_groceries[COL_GROC_CAT]
bills_collection = db_energy[COL_ENERGY]
gas_collection = db_gas[COL_GAS]
water_collection = db_water[COL_WATER]

warranties = db_warranties[COL_WARRANTIES]
newspaper = db_newspaper[COL_NEWSPAPER]



def serialize_document(doc):    
    if '_id' in doc:
        doc['_id'] = str(doc['_id'])
    return doc

#get month in words
def getMonthName(monthNo):
    month_map = {
        1: "january", 2: "february", 3: "march", 4: "april",
        5: "may", 6: "june", 7: "july", 8: "august",
        9: "september", 10: "october", 11: "november", 12: "december"
    }
    
    return month_map.get(monthNo, None)


# def handle_user_login(username, password):
#     """Handles login for regular users with email and password."""
#     user = users.find_one({"email": username})

#     if not user:
#         return jsonify({"error": "Invalid user"}), 400

#     if not bcrypt.check_password_hash(user['password'], password):
#         return jsonify({"error": "Invalid password"}), 400

#     # Check if the user has a home associated
#     home = homes_collection.find_one({'created_by': str(user['_id'])})
#     home_id = str(home['_id']) if home else None

    

#     token = create_access_token(
#     identity={'userId': str(user['_id']), 'role': "Owner", 'homeId': home_id}
# )

#     print(bool(home))
#     return jsonify({
#         "Message": "Login success",
#         "token": token,
#         "username": f"{user['firstname']} {user['lastname']}",
#         "role": "Owner",
#         "flag": user['isApproved']
#     }), 200


# def handle_maid_login(name, pin):
#     """Handles login for maids with name and PIN."""
#     househelps = list(househelps_collection.find({"personal_info.name": name}))

#     if not househelps:
#         return jsonify({"error": "Invalid maid"}), 400

#     for maid in househelps:
#         if str(maid.get('pin')) == pin:
#             role = categories_collection.find_one({"_id": ObjectId(maid.get('category_id'))})
#             if not role:
#                 return jsonify({"error": "Role not found"}), 400

#             home_id = str(maid.get('homeId')) if 'homeId' in maid else None

#             token = create_access_token(
#                 identity={'userId': str(maid['_id']), 'role': role['category_name'], 'homeId': home_id},
#                 expires_delta=datetime.timedelta(hours=2)
#             )

#             return jsonify({
#                 "Message": "Login success",
#                 "token": token,
#                 "username": maid['personal_info']['name'],
#                 'homeId': home_id,
#                 'role': role['category_name']
#             }), 200

#     return jsonify({"error": "Invalid PIN"}), 400

def handle_user_login(username, password):
    """Handles login for regular users with email and password."""
    user = users.find_one({"email": username})

    if not user:
        return jsonify({"error": "Invalid user"}), 400

    if not bcrypt.check_password_hash(user['password'], password):
        return jsonify({"error": "Invalid password"}), 400

    # home = homes_collection.find_one({'created_by': str(user['_id'])})
    home = homes_collection.find_one({'members': str(user['_id'])})
    home_id = str(home['_id']) if home else None


    # access_token = create_access_token(
    #     identity={'userId': str(user['_id']), 'role': "Owner", 'homeId': home_id}
    # )
    access_token = create_access_token(
    identity=json.dumps({
        'userId': str(user['_id']),
        'role': "Owner",
        'homeId': home_id
    })
)
    refresh_token = create_refresh_token(identity={'userId': str(user['_id']),'role': "Owner", 'homeId': home_id})

    return jsonify({
        "Message": "Login success",
        "token": access_token,
        "refresh_token": refresh_token,
        "username": f"{user['firstname']} {user['lastname']}",
        "role": "Owner",
        "flag": user['isApproved']
    }), 200


def handle_maid_login(name, pin):
    """Handles login for maids with name and PIN."""
    househelps = list(househelps_collection.find({"personal_info.name": name}))

    if not househelps:
        return jsonify({"error": "Invalid maid"}), 400

    for maid in househelps:
        if str(maid.get('pin')) == pin:
            role = categories_collection.find_one({"_id": ObjectId(maid.get('category_id'))})
            if not role:
                return jsonify({"error": "Role not found"}), 400

            home_id = str(maid.get('homeId')) if 'homeId' in maid else None

      
            access_token = create_access_token(
                identity=json.dumps({'userId': str(maid['_id']), 'role': role['category_name'], 'homeId': home_id}),
                expires_delta=datetime.timedelta(hours=2)
            )
            
            refresh_token = create_refresh_token(identity={'userId': str(maid['_id']), 'role': role['category_name'], 'homeId': home_id})

            return jsonify({
                "Message": "Login success",
                "token": access_token,
                "refresh_token": refresh_token,
                "username": maid['personal_info']['name'],
                'homeId': home_id,
                'role': role['category_name']
            }), 200

    return jsonify({"error": "Invalid PIN"}), 400


# @app.route('/refresh', methods=['POST'])
# @jwt_required(refresh=True)
# def refresh_token():
#     current_user = get_jwt_identity()
#     new_access_token = create_access_token(identity=current_user)
#     return jsonify({"token": new_access_token}), 200


@app.route('/greet', methods=['GET'])

def greet():
   
    try:
      
        return jsonify({"message":"Hi vinu"}), 200
    except Exception as e:
        print(" Error:", e)
        return jsonify({"error": "Invalid request"}), 401
    
@app.route('/images/<path:filename>')
def serve_image(filename):
    return send_from_directory('images', filename)


@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh_token():
   
    try:
        current_user = json.loads(get_jwt_identity())   # Validate the refresh token
        # print("Refresh Token Used by:", current_user)  # Debugging log
        new_access_token = create_access_token(identity=current_user)
        return jsonify({"token": new_access_token}), 200
    except Exception as e:
        print("Refresh Error:", e)
        return jsonify({"error": "Invalid refresh token"}), 401

@app.route('/register', methods=['POST'])
def register_user():
    try:
        data = request.json
        required_fields = ['firstname', 'lastname', 'building_name', 'flat_no', 'email', 'password']
        if not all(data.get(field) for field in required_fields):
            return jsonify({"error": "All fields are required."}), 400

        firstname, lastname = data['firstname'], data['lastname']
        building_name, flat_no = data['building_name'], data['flat_no']
        email, password = data['email'], data['password']

        # Check if the email is already registered
        if users.find_one({'email': email}):
            return jsonify({"error": "Email already registered"}), 400

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Check if the home already exists
        existing_home = homes_collection.find_one({
            'building_name': building_name,
            'flat_no': flat_no
        })

        is_approved = not bool(existing_home)

        # Prepare user data
        user_data = {
            'firstname': firstname,
            'lastname': lastname,
            'email': email,
            'password': hashed_password,
            'isApproved': is_approved,
            'role': "Owner" if is_approved else "member"
        }

        # Insert user first to get user_id
        user_id = str(users.insert_one(user_data).inserted_id)

        # If home doesn't exist, create a new one and add the user as the owner
        if is_approved:
            new_home = {
                'building_name': building_name,
                'flat_no': flat_no,
                'created_by': user_id,
                'members': [user_id],
                'created_at': datetime.datetime.utcnow()
            }
            new_home_id = str(homes_collection.insert_one(new_home).inserted_id)
            user_data['homeId'] = new_home_id
        else:
            # If home exists, set the homeId to the existing home ID and add user as a member
            user_data['homeId'] = str(existing_home['_id'])
            homes_collection.update_one(
                {'_id': existing_home['_id']},
                {'$addToSet': {'members': user_id}}
            )

        # Update user with the assigned homeId
        users.update_one({'_id': ObjectId(user_id)}, {'$set': {'homeId': user_data['homeId']}})

        message = "User registered successfully! " + (
            "Home added successfully!" if is_approved else "Home already exists and approval is pending."
        )

        return jsonify({"message": message}), 201

    except Exception as e:
        print(f"Error occurred during registration: {e}")
        return jsonify({"error": "An error occurred during registration. Please try again later."}), 500


@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        username = data.get('email')
        password = data.get('password')

        if not username or not password:
            return jsonify({"error": "Missing email or password"}), 400

        # Check if username is email for user login
        if re.match(r"[^@]+@[^@]+\.[^@]+", username):
            return handle_user_login(username, password)
        else:
            return handle_maid_login(username, password)

    except PyMongoError as e:
        print(f"Database error: {e}")
        return jsonify({"error": "Database error, please try again later."}), 500

    except Exception as e:
        print(f"Unexpected error: {e}")
        traceback.print_exc()
        return jsonify({"error": "An unexpected error occurred, please try again later."}), 500
    

@app.route('/getPendingMembers', methods=['GET'])
@jwt_required()
def get_pending_members():
    try:
      
        user = json.loads(get_jwt_identity()) 
        home_id = user.get('homeId')

        if not home_id:
            return jsonify({"error": "Home ID not found in token"}), 400

        members = list(users.find(
            {"homeId": home_id, "role": "member","isApproved":False},
            {"firstname": 1, "email": 1, "_id": 1} 
        ))

        for member in members:
            member['_id'] = str(member['_id'])

        if not members:
            return jsonify({"message": "No Pending members "}), 404
        
      

        return jsonify({"members": members}), 200

    except PyMongoError as e:
    
        print(f"Database error while fetching members: {e}")
        return jsonify({"error": "Database error, please try again later."}), 500

    except Exception as e:
        print(f"Unexpected error while fetching members: {e}")
        return jsonify({"error": "An unexpected error occurred, please try again later."}), 500


@app.route('/getMembers', methods=['GET'])
@jwt_required()
def get_members():
    try:
      
        user = json.loads(get_jwt_identity()) 
        home_id = user.get('homeId')

        if not home_id:
            return jsonify({"error": "Home ID not found in token"}), 400

        members = list(users.find(
            {"homeId": home_id, "role": "member","isApproved":True},
            {"firstname": 1, "email": 1, "_id": 1} 
        ))

        for member in members:
            member['_id'] = str(member['_id'])

        if not members:
            return jsonify({"message": "No members found for this home"}), 404
        
      

        return jsonify({"members": members}), 200

    except PyMongoError as e:
    
        print(f"Database error while fetching members: {e}")
        return jsonify({"error": "Database error, please try again later."}), 500

    except Exception as e:
        print(f"Unexpected error while fetching members: {e}")
        return jsonify({"error": "An unexpected error occurred, please try again later."}), 500


@app.route('/familyMembers/updateStatus', methods=['PUT'])
@jwt_required()
def update_member_status():
    try:
        user = json.loads(get_jwt_identity()) 
        home_id = user.get('homeId')
        member_id = request.json.get('memberId')
        status = request.json.get('status')

        if not home_id:
            return jsonify({"error": "Home ID not found in token"}), 400

        if status not in ['approved', 'rejected', 'pending']:
            return jsonify({"error": "Invalid status. Must be 'approved', 'rejected', or 'pending'"}), 400

        member = users.find_one({'_id': ObjectId(member_id), "homeId": home_id, "role": "member"})

        if not member:
            return jsonify({"error": "Member not found or does not belong to the specific home"}), 404

        if status == 'rejected':
            # Delete the member from the collection if the status is "rejected"
            delete_result = users.delete_one({"_id": ObjectId(member_id)})
            if delete_result.deleted_count == 0:
                return jsonify({"error": "Failed to delete member"}), 404
            return jsonify({"message": "Member rejected and deleted successfully"}), 200

        elif status == 'pending':
            # Set isApproved to False if status is "pending"
            update_result = users.update_one(
                {"_id": ObjectId(member_id)},
                {"$set": {"isApproved": False}}
            )
            if update_result.matched_count == 0:
                return jsonify({"error": "Failed to update member status"}), 404
            return jsonify({"message": "Member status set to pending"}), 200

        elif status == 'approved':
            # Set isApproved to True if status is "approved"
            update_result = users.update_one(
                {"_id": ObjectId(member_id)},
                {"$set": {"isApproved": True}}
            )
            if update_result.matched_count == 0:
                return jsonify({"error": "Failed to update member status"}), 404
            return jsonify({"message": "Member approved successfully"}), 200

    except PyMongoError as e:
        print(f"Database error while updating member status: {e}")
        return jsonify({"error": "Database error, please try again later"}), 500

    except Exception as e:
        print("Unexpected error while updating member status:", e)
        return jsonify({"error": "An error occurred, please try again later"}), 500
        

@app.route('/home/add', methods=['POST'])
@jwt_required()
def add_home():

  
    data = request.json
    name = data.get('building_name')
    flat_no = data.get('flat_no')
    current_user = json.loads(get_jwt_identity())  
    user_id = current_user['userId']  

 
    home = homes_collection.find_one({'building_name': name, 'flat_no': flat_no})

    if home:
        return jsonify({'error': 'Home already exists'}), 400


    new_home = {
        'building_name': name,
        'flat_no': flat_no,
        'created_by': user_id,
        'created_at': datetime.datetime.utcnow()
    }

    result = homes_collection.insert_one(new_home)
    home_id = result.inserted_id

    auth_db = client['Authentication']  
    users_collection = auth_db['users'] 

  
    users_collection.update_one(
        {'_id': ObjectId(user_id)},  
        {'$set': {'homeId': str(home_id)}} 
    )

    return jsonify({'message': 'Home added successfully!', 'homeId': str(home_id)}), 201


@app.route('/home', methods=['GET'])
@jwt_required()
def get_home():

    # identity_str = get_jwt_identity()
    # current_user = json.loads(identity_str) 

    current_user = json.loads(get_jwt_identity()) 

    # current_user = get_jwt_identity()
    user_id = current_user['userId']
    home = homes_collection.find_one({
        "$or": [
            {"created_by": user_id},
            {"members": user_id}
        ]
    })
  
    if not home:
        return jsonify({'error': 'Home not found'}), 404

    return jsonify({"name":home['building_name'],"flat":home['flat_no']}), 200


@app.route('/groceries', methods=['GET', 'OPTIONS'])
@jwt_required()
def getGroceries():
    try:
     
        groceries_list = list(groceries.find())
  
        for grocery in groceries_list:
            grocery['_id'] = str(grocery['_id'])
        
      
        categories_data = list(categories.find())
        

        categories_dict = {
            str(category['_id']): {
                "name": category['name'],
                "sub_categories": {str(sub['_id']): sub['name'] for sub in category.get('sub_category', [])}
            }
            for category in categories_data
        }
        
        for grocery in groceries_list:
            category_info = categories_dict.get(grocery.get('category_id'))
            if category_info:
                grocery['category_name'] = category_info['name']
                grocery['sub_category_name'] = category_info['sub_categories'].get(grocery.get('sub_category_id'))
        
        return jsonify({"groceries": groceries_list}), 200
    
    except PyMongoError as e:
        print(f"Database error: {e}")
        return jsonify({"error": "Database error, please try again later."}), 500

    except Exception as e:
        print(f"Unexpected error: {e}")
        return jsonify({"error": "An unexpected error occurred, please try again later."}), 500


@app.route('/groceries/add', methods=['POST'])
@jwt_required()
def mark_out_of_stock():
    try:
       
        data = request.json
        grocery_id = data.get("_id")
        
     
        current_user = json.loads(get_jwt_identity()) 
        created_by = current_user['userId']
        home_id = current_user['homeId']
        user_role = current_user.get('role')  
        
        allowed_roles = ['Owner', 'maid', 'Cook']

        if user_role not in allowed_roles:
            return jsonify({"error": "Access denied. You do not have permission to mark items as out of stock."}), 403

        grocery_item = groceries.find_one({"_id": ObjectId(grocery_id)})
        if not grocery_item:
            return jsonify({"error": "Item not found"}), 404

        existing_item = groceries_requests.find_one({"name": grocery_item["name"], "homeId": home_id})
        if existing_item:
            return jsonify({"error": "Item is already marked as out of stock"}), 400

      
        groceries_requests.insert_one({
            "name": grocery_item["name"],
            "homeId": home_id,
            "createdBy": created_by,
            "photo": grocery_item["photo"],
            "status": "pending",
            "added_at": datetime.datetime.now()
        })

        return jsonify({"message": f"{grocery_item['name']} marked as out of stock"}), 200

    except PyMongoError as e:
        print(f"Database error: {e}")
        return jsonify({"error": "Database error, please try again later."}), 500

    except Exception as e:
        print(f"Unexpected error: {e}")
        return jsonify({"error": "An unexpected error occurred, please try again later."}), 500


@app.route('/groceries/outofstock', methods=['GET'])
@jwt_required()
def get_out_of_stock():
   
    current_user = json.loads(get_jwt_identity()) 
    role = current_user.get('role')
    home_id = current_user['homeId']

  
    if role != "Owner":
        return jsonify({"error": "Unauthorized access"}), 403  
 
    if not home_id:
        return jsonify({"error": "homeId is required"}), 400  

    out_of_stock_items = list(groceries_requests.find(
        {"homeId": home_id},
        {'_id': 1, 'name': 1, 'homeId': 1, 'createdBy': 1, 'photo': 1}
    ))

    for grocery in out_of_stock_items:
            grocery['_id'] = str(grocery['_id'])

    return jsonify({"out_of_stock": out_of_stock_items}), 200 

@app.route('/groceries/outofstock/update', methods=['PUT'])
@jwt_required()
def update_out_of_stock_status():
    data = request.json
    grocery_id = data.get("_id")
    current_user = json.loads(get_jwt_identity()) 
    role = current_user.get('role')

 
    if role != "Owner":
        return jsonify({"error": "Unauthorized access"}), 403
    
    if not grocery_id:
        return jsonify({"error": "Grocery ID is required"}), 400
    
    grocery_item = groceries_requests.find_one({"_id": ObjectId(grocery_id)})
    if not grocery_item:
        return jsonify({"error": "Item not found"}), 404

    groceries_requests.update_one(
        {"_id": ObjectId(grocery_id)},
        {"$set": {"status": "later", "ordered_at": datetime.datetime.now()}}
    )

    return jsonify({"message": f"{grocery_item['name']} status updated to later"}), 200


@app.route('/groceries/outofstock/delete', methods=['DELETE'])
@jwt_required()
def delete_out_of_stock():
    data = request.json
    grocery_id = data.get("_id")
    current_user = json.loads(get_jwt_identity()) 
    role = current_user.get('role')

 
    if role != "Owner":
        return jsonify({"error": "Unauthorized access"}), 403

    if not grocery_id:
        return jsonify({"error": "Grocery ID is required"}), 400

    grocery_item = groceries_requests.find_one({"_id": ObjectId(grocery_id)})
    if not grocery_item:
        return jsonify({"error": "Item not found"}), 404

    groceries_requests.delete_one({"_id": ObjectId(grocery_id)})

    return jsonify({"message": f"{grocery_item['name']} deleted from out of stock list"}), 200


@app.route('/househelp/categories/add', methods=['POST'])

def add_category():
    data = request.json
    category_name = data.get('category_name')



    existing_category = categories_collection.find_one({'category_name': category_name})
    if existing_category:
        return jsonify({'error': 'househelp category already exists'}), 400

    category = {
        'category_name': category_name,
        'created_at': datetime.datetime.utcnow()
    }
    categories_collection.insert_one(category)

    return jsonify({'message': 'househelp category added successfully!'}), 201


@app.route('/househelp/categories/all', methods=['GET'])
def get_categories():
    try:
        categories_cursor = categories_collection.find()
        categories = list(categories_cursor)  

        if not categories:
            return jsonify({'error': 'No data found'}), 404

        for category in categories:
            category['_id'] = str(category['_id'])

        return jsonify(categories), 200

    except Exception as e:
        print(f"Error fetching categories: {e}")
        return jsonify({'error': 'Internal Server Error'}), 500



@app.route('/househelp/add', methods=['POST'])
@jwt_required()
def create_househelp():
    try:
        data = request.json

        current_user = json.loads(get_jwt_identity()) 
        user_id = current_user['userId']
        home_id = current_user.get('homeId')  

        category_name = data.get('role')
        category = categories_collection.find_one({'category_name': category_name})
        if not category:
            return jsonify({'error': 'Category not found'}), 400

        adhar = data.get('adhar')

        existing_househelp = househelps_collection.find_one({'adhar': adhar, 'createdBy': user_id})
        if existing_househelp:
            return jsonify({"error": "Adhar number already exists"}), 400

        def generate_unique_pin():
            while True:
                pin = random.randint(100000, 999999) 
                if not househelps_collection.find_one({'pin': pin}): 
                    return pin

        unique_pin = generate_unique_pin()

        househelp = {
            'category_id': str(category['_id']),
            'personal_info': {
                'name': data.get('name'),
                'phone_number': data.get('phone_number'),
                'photo': data.get('photo'),
                'address': data.get('address'),
                'gender': data.get('gender')
            },
            'financial_info': {
                'start_date': datetime.datetime.strptime(data.get('start_date'), '%Y-%m-%d'),
                'end_date': datetime.datetime.strptime(data.get('end_date'), '%Y-%m-%d') if data.get('end_date') else None,
                'value': {
                    'daily': data.get('daily_value'),
                    'weekly': data.get('weekly_value'),
                    'monthly': data.get('monthly_value'),
                    'yearly': data.get('yearly_value'),
                },
                'payment_details': {
                    "payment_mode": data.get('payment_mode'),
                    'UPI_ID': data.get('UPI_ID'),
                    'BANK': {
                        'account_number': data.get('acc'),
                        'ifsc': data.get('ifsc'),
                    }
                },
                'payment_type': data.get('payment_type'),
                
                'total_value': data.get('total_value'),
                'payment_date': data.get('payment_date')  
            },
            'kyc_info': {
                'adhar': adhar,
                'verified': data.get('verified', False)
            },
            'payment_status': data.get('payment_status'),
            'createdBy': user_id,
            'homeId': home_id,  
            'pin': unique_pin,  
            'created_at': datetime.datetime.utcnow()
        }

        househelps_collection.insert_one(househelp)

        return jsonify({'message': 'Househelp created successfully!',"pin":unique_pin}), 201

    except PyMongoError as e:
        print(f"Database error: {e}")
        return jsonify({"error": "Database error, please try again later."}), 500

    except ValueError as ve:
        print(f"Value error: {ve}")
        return jsonify({"error": "Invalid data format, please check your inputs."}), 400

    except Exception as e:
        print(f"Unexpected error: {e}")
        traceback.print_exc()  
        return jsonify({"error": "An unexpected error occurred, please try again later."}), 500

   


@app.route('/househelp/all', methods=['GET'])
@jwt_required()
def get_all_househelps():

    try:
        current_user = json.loads(get_jwt_identity()) 
        user_id = current_user['userId']
        home_id = current_user['homeId']

     
        category_name = request.args.get('role')

       

        category = categories_collection.find_one({'category_name': category_name})
        if not category:
            return jsonify({'error': 'Category not found'}), 404

        category_id = str(category['_id'])

        househelps = list(househelps_collection.find({'homeId': home_id, 'category_id': category_id}))

        if not househelps:
            return jsonify({'error': 'No househelp found '}), 404


        for househelp in househelps:
            househelp['_id'] = str(househelp['_id'])
            househelp['category_id'] = str(househelp['category_id'])
            househelp['category_name'] = category_name

        return jsonify({'househelps': househelps}), 200
    except Exception as e:
        return jsonify({"error":e})
    

@app.route('/househelp', methods=['GET'])
@jwt_required()
def get_househelps():
    try:
      
        current_user = json.loads(get_jwt_identity()) 
        user_id = current_user['userId']

   
        househelps = list(househelps_collection.find({'createdBy': user_id}, {'_id': 1, 'category_id': 1}))

        if not househelps:
            return jsonify({'error': 'No househelp found'}), 404

        househelps_data = []
        for househelp in househelps:
     
            househelp['_id'] = str(househelp['_id'])

            category = categories_collection.find_one({'_id':ObjectId(househelp['category_id'])}, {'category_name': 1})

            if category:
                househelp['category_name'] = category['category_name']
            else:
                househelp['category_name'] = "Unknown Category"

            househelps_data.append(househelp)

        return jsonify({'househelps': househelps_data}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route('/househelp/find', methods=['GET'])
@jwt_required()
def get_househelp():
    try:
        
        househelp_id = request.args.get('id')
        if not househelp_id:
            return jsonify({'error': 'Househelp ID is required'}), 400

        househelp = househelps_collection.find_one({'_id': ObjectId(househelp_id)})
        if not househelp:
            return jsonify({'error': 'Househelp not found'}), 404

        househelp['_id'] = str(househelp['_id'])
        househelp['category_id'] = str(househelp['category_id'])

        category = categories_collection.find_one({'_id': ObjectId(househelp['category_id'])})
        househelp['category_name'] = category['category_name'] if category else 'Unknown'

        return jsonify(househelp), 200

    except Exception as e:
        print(f"Error occurred: {e}")
        return jsonify({'error': 'An error occurred while fetching househelp details'}), 500



# @app.route('/energyConsumption/addData', methods=['POST'])
# @jwt_required()
# def add_bill():
#     try:
#         data = request.json
#         current_user = get_jwt_identity()
#         user_id = current_user['userId']
#         homeId = current_user['homeId']
 
#         data['createdBy'] = str(user_id)
#         data['homeId'] = homeId
        
#         data['readingDate'] = datetime.datetime.strptime(data['readingDate'], '%Y-%m-%d')

       

#         result = bills_collection.insert_one(data)
        
#         data['_id'] = str(result.inserted_id)

#         return jsonify({"message": "Bill added successfully!", "data": data}), 201
    
#     except Exception as e:
#         return jsonify({"error": str(e)}), 400

@app.route('/energyConsumption/addData', methods=['POST'])
@jwt_required()
def add_bill():
    try:
        data = request.json
        current_user = json.loads(get_jwt_identity()) 
        user_id = current_user['userId']
        homeId = current_user['homeId']

    
        reading_date = datetime.datetime.strptime(data.get('readingDate'), '%Y-%m-%d')

        existing_bill = bills_collection.find_one({
            "homeId": homeId,
            "readingDate": {
                "$gte": reading_date.replace(day=1),
                "$lt": (reading_date.replace(day=1) + datetime.timedelta(days=31)).replace(day=1)
            }
        })

        if existing_bill:
            return jsonify({
                "error": "Data for the given month is already present.",
                "existingData": {
                    "_id": str(existing_bill["_id"]),
                    "readingDate": existing_bill["readingDate"].strftime('%Y-%m-%d'),
                    "amount": existing_bill.get("amount"),
                    "units": existing_bill.get("units")
                }
            }), 409

 
        data['createdBy'] = str(user_id)
        data['homeId'] = homeId
        data['readingDate'] = reading_date

        result = bills_collection.insert_one(data)
        data['_id'] = str(result.inserted_id)

        return jsonify({"message": "Bill added successfully!", "data": data}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 400



@app.route('/get_last_three_months', methods=['GET'])
@jwt_required()
def get_last_three_months():
    try:
        current_user = json.loads(get_jwt_identity()) 


        homeId = current_user['homeId']

        three_months_ago = datetime.datetime.now() - datetime.timedelta(days=90)

        bills = list(bills_collection.find({
            "homeId": homeId,
            "readingDate": {"$gte": three_months_ago}
        }).sort("readingDate", 1))

        if not bills:
            return jsonify({"error": "No consumption found "}), 404

        serialized_bills = [serialize_document(bill) for bill in bills]

        return jsonify(serialized_bills), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/getConsumption', methods=['GET'])
@jwt_required()
def get_energy_consumption():
    try:
        current_user = json.loads(get_jwt_identity()) 
        user_id = current_user['userId']
        
      
  
        month = int(request.args.get('month'))
        year = int(request.args.get('year'))

        target_month = month + 1 if month < 12 else 1
        target_year = year if month < 12 else year + 1

    

        current_month_start = datetime.datetime(target_year, target_month, 1)
        
        print(current_month_start)
        if month == 12:
            next_month_start = datetime.datetime(target_year + 1, 1, 1)
        else:
            next_month_start = datetime.datetime(target_year, target_month + 1, 1)
        
        print(next_month_start)

        bills = bills_collection.find_one({
            "createdBy": user_id,
            "readingDate": {
                "$gte": current_month_start,
                "$lt": next_month_start
            }
        })
        
        if not bills:
            return jsonify({"message": f"No bill found for the specified month {month} and year {year}."}), 404

        # Extract and return the unitsConsumed
        units_consumed = bills.get('consumptionDetails', {}).get('unitsConsumed', 0)

        monthName = getMonthName(month)
       
        return jsonify({"unitsConsumed": units_consumed, "month": monthName, "year": year}), 200

    except Exception as e:
        print(e)
        return jsonify({"error": str(e)}), 500


@app.route('/get_current_month', methods=['GET'])
@jwt_required()
def get_current_month():
    try:

        current_user = json.loads(get_jwt_identity()) 
        user_id = current_user['userId']

        current_month_start = datetime.datetime(datetime.datetime.now().year, datetime.datetime.now().month, 1)
        bills = list(bills_collection.find({
            "createdBy": user_id,
            "readingDate": {"$gte": current_month_start}
        }).sort("readingDate", 1))

        if not bills:
            return jsonify({"message": "No bill found for the current month."}), 404
        serialized_bills = [serialize_document(bills) for bill in bills]
        return jsonify(bills[0]), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    


@app.route('/gas_consumption/last_three_months', methods=['GET'])
@jwt_required()
def get_last_three_months_gas_consumption():
    try:
       
        current_user = json.loads(get_jwt_identity()) 
        homeId = current_user['homeId']

        three_months_ago = datetime.datetime.now() - datetime.timedelta(days=90)

        records = gas_collection.find({
            "homeId": homeId,
            "delivered_date": {"$gte": three_months_ago}
        }).sort("delivered_date", 1)

        # Convert records to a serializable format and check if any records were found
        result = [{**record, "_id": str(record["_id"])} for record in records]
        
        if not result:
            return jsonify({"error": "No gas consumption re cords found for the last three months"}), 404

        return jsonify(result), 200

    except Exception as e:
        return jsonify({"error": "Failed to fetch gas consumption records", "message": str(e)}), 500


@app.route('/gasConsumption/addData', methods=['POST'])
@jwt_required()
def add_gas_consumption():
    try:
        # Extract JSON data from request
        data = request.json
        current_user = json.loads(get_jwt_identity()) 
        
        # Add user and home information
        user_id = current_user['userId']
        homeId = current_user['homeId']
        data['createdBy'] = str(user_id)
        data['homeId'] = homeId


        record = {
            "delivered_date": datetime.datetime.strptime(data.get("deliveredDate"), '%Y-%m-%d'),
            "total_weight": data.get("totalWeight"),
            "amount": data.get("amount"),
            "createdBy": data['createdBy'],
            "homeId": data['homeId']
        }
        
        # Insert the record and get the ID
        result = gas_collection.insert_one(record)
        record['_id'] = str(result.inserted_id)

        return jsonify({"message": "Gas consumption record added successfully!", "data": record}), 201

    except Exception as e:
        return jsonify({"error": "Failed to add gas consumption record", "message": str(e)}), 400



@app.route('/gas_consumption/<id>', methods=['GET'])
def get_gas_consumption_by_id(id):
    try:
        record = gas_collection.find_one({"_id": ObjectId(id)})
        if record:
            record["_id"] = str(record["_id"])
            return jsonify(record), 200
        else:
            return jsonify({"error": "Gas consumption record not found"}), 404
    except Exception as e:
        return jsonify({"error": "Failed to fetch gas consumption record", "message": str(e)}), 500


@app.route('/gas_consumption/<id>', methods=['PUT'])
def update_gas_consumption(id):
    data = request.json
    try:
        updated_record = {
            "bill_number": data["bill_number"],
            "consumer_number": data["consumer_number"],
            "delivered_date": data["delivered_date"],
            "total_weight": data["total_weight"],
            "amount": data["amount"]
        }
        result = gas_collection.update_one({"_id": ObjectId(id)}, {"$set": updated_record})
        if result.modified_count > 0:
            return jsonify({"_id": id, **updated_record}), 200
        else:
            return jsonify({"error": "No changes made or gas consumption record not found"}), 404
    except Exception as e:
        return jsonify({"error": "Failed to update gas consumption record", "message": str(e)}), 500


@app.route('/gas_consumption/<id>', methods=['DELETE'])
def delete_gas_consumption(id):
    try:
        result = gas_collection.delete_one({"_id": ObjectId(id)})
        if result.deleted_count > 0:
            return jsonify({"message": "Gas consumption record deleted"}), 200
        else:
            return jsonify({"error": "Gas consumption record not found"}), 404
    except Exception as e:
        return jsonify({"error": "Failed to delete gas consumption record", "message": str(e)}), 500


@app.route('/waterConsumption/last_three_months', methods=['GET'])
@jwt_required()
def get_last_three_months_water_consumption():
    try:
        current_user = json.loads(get_jwt_identity()) 
        home_id = current_user['homeId']
        
        three_months_ago = datetime.datetime.now() - datetime.timedelta(days=90)

        records = water_collection.find({
            "reading_date": {"$gte": three_months_ago},
            "homeId": home_id
        })
        
        result = [
            {
                "_id": str(record["_id"]),      
                "reading_date": record["reading_date"].strftime("%Y-%m-%d"),
                "due_date": record["due_date"].strftime("%Y-%m-%d"),
                "consumption_liters": record["consumption_liters"],
                "water_charges": record["water_charges"],
                "other_charges": record["other_charges"],
                "total_amount": record["total_amount"]
            }
            for record in records
        ]
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": "Failed to fetch water consumption records", "message": str(e)}), 500


@app.route('/waterConsumption/addData', methods=['POST'])
@jwt_required()
def add_water_consumption():
    data = request.json
    current_user = json.loads(get_jwt_identity()) 
    
    user_id = current_user['userId']
    home_id = current_user['homeId']
    data['createdBy'] = str(user_id)
    data['homeId'] = home_id

    try:
        required_fields = [
             "readingDate", "dueDate",
            "consumptionInLtrs", "waterCharges",
            "otherCharges", "totalAmount"
        ]
        
     
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Missing field: {field}"}), 400

        reading_date = datetime.datetime.strptime(data["readingDate"], "%Y-%m-%d")
        due_date = datetime.datetime.strptime(data["dueDate"], "%Y-%m-%d")


        record = {
           
            "reading_date": reading_date,
            "due_date": due_date,
           
            "consumption_liters": float(data["consumptionInLtrs"]),
            "water_charges": float(data["waterCharges"]),
            "other_charges": float(data["otherCharges"]),
            "total_amount": float(data["totalAmount"]),
            "createdBy": user_id, 
            "homeId": home_id
        }
        
     
        result = water_collection.insert_one(record)

        return jsonify({
            "_id": str(result.inserted_id),
            "reading_date": reading_date.strftime("%Y-%m-%d"), 
            "due_date": due_date.strftime("%Y-%m-%d"),
            "consumption_liters": float(data["consumptionInLtrs"]),
            "water_charges": float(data["waterCharges"]),
            "other_charges": float(data["otherCharges"]),
            "total_amount": float(data["totalAmount"]),
            "createdBy": str(user_id),
            "homeId": str(home_id)
        }), 201

    except Exception as e:
        return jsonify({"error": "Failed to add water consumption record", "message": str(e)}), 500

@app.route('/water_consumption/<id>', methods=['GET'])
def get_water_consumption_by_id(id):
    try:

        record = water_collection.find_one({"_id": ObjectId(id)})
        if record:
        
            record["_id"] = str(record["_id"])
            record["createdBy"] = str(record["createdBy"])
            record["homeId"] = str(record["homeId"])
            return jsonify(record), 200
        else:
            return jsonify({"error": "Water consumption record not found"}), 404
    except Exception as e:
        return jsonify({"error": "Failed to fetch water consumption record", "message": str(e)}), 500


@app.route('/water_consumption/<id>', methods=['PUT'])
def update_water_consumption(id):
    data = request.json
    try:
        updated_record = {
            "RR_number": data["RR_number"],
            "consumer_number": data["consumer_number"],
            "bill_number": data["bill_number"],
            "reading_date": data["reading_date"],
            "due_date": data["due_date"],
            "previous_reading": data["previous_reading"],
            "present_reading": data["present_reading"],
            "consumption_liters": data["consumption_liters"],
            "water_charges": data["water_charges"],
            "other_charges": data["other_charges"],
            "total_amount": data["total_amount"]
        }
        result = water_collection.update_one({"_id": ObjectId(id)}, {"$set": updated_record})
        if result.modified_count > 0:
            return jsonify({"_id": id, **updated_record}), 200
        else:
            return jsonify({"error": "No changes made or water consumption record not found"}), 404
    except Exception as e:
        return jsonify({"error": "Failed to update water consumption record", "message": str(e)}), 500


@app.route('/water_consumption/<id>', methods=['DELETE'])
def delete_water_consumption(id):
    try:
        result = water_collection.delete_one({"_id": ObjectId(id)})
        if result.deleted_count > 0:
            return jsonify({"message": "Water consumption record deleted"}), 200
        else:
            return jsonify({"error": "Water consumption record not found"}), 404
    except Exception as e:
        return jsonify({"error": "Failed to delete water consumption record", "message": str(e)}), 500


from bson import ObjectId
import datetime
from flask import request, jsonify
from flask_jwt_extended import jwt_required

@app.route('/househelp/updatePaymentStatus', methods=['PUT'])
@jwt_required()
def update_payment_status():
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        print(user_id)
        if not ObjectId.is_valid(user_id):
            return jsonify({"error": "Invalid user ID format"}), 400

        payment_status = data.get('payment_status')

        if not payment_status:
            return jsonify({"error": "Missing required field: payment_status"}), 400

        user = househelps_collection.find_one({"_id": ObjectId(user_id)})
  
        if not user:
            return jsonify({"error": "User not found"}), 404
  
        update_data = {
            "payment_status": payment_status,
            "updated_at": datetime.datetime.utcnow()
        }


        result = househelps_collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": update_data}
        )
        print(result)
        if result.matched_count == 0:
            return jsonify({"error": "No househelp found to update"}), 404

        return jsonify({"message": "Payment status updated successfully"}), 200

    except Exception as e:
     
        return jsonify({"error": str(e)}), 500


@app.route('/reminders', methods=['GET'])
@jwt_required()
def reminders():
    current_user = json.loads(get_jwt_identity()) 
    home_id = current_user['homeId']
    today = datetime.datetime.today()
    next_week = today + timedelta(days=7)

    # Initialize the reminders dictionary
    reminders = {
        "family_members_approval": 0,
        "electricity_due_reminders": [],
        "groceries_pending": 0,
        "househelp_pending_payments": []
    }

    # Family members awaiting approval
    family_members_approval = users.count_documents({"homeId": home_id, "isApproved": False})
    reminders["family_members_approval"] = family_members_approval

    # Electricity bills due within the next 7 days
    electricity_due_bills = bills_collection.find({
        "homeId": home_id,
        "BillDueDate": {"$lte": next_week, "$gte": today}
    })
    for bill in electricity_due_bills:
        days_left = (bill["BillDueDate"] - today).days
        reminders["electricity_due_reminders"].append(f"Electricity bill pending in {days_left} days")

    # Pending groceries that need ordering
    groceries_pending_count = groceries_requests.count_documents({
    "homeId": home_id,
    "status": {"$in": ["pending", "later"]}
    })
    reminders["groceries_pending"] = groceries_pending_count

    # Househelp with pending payments
    pending_househelps = househelps_collection.find({
        "homeId": home_id,
        "payment_status": "Pending"
    })
    for househelp in pending_househelps:
        name = househelp["personal_info"].get("name", "Unknown")
        reminders["househelp_pending_payments"].append(f"{name}'s salary pending")

    return jsonify(reminders), 200


@app.route('/image/upload', methods=['PUT'])
@jwt_required()
def upload_image():
   try:
      data=request.json
      current_user = json.loads(get_jwt_identity()) 
      user_id =  current_user['userId']
      url=data.get('url')    
 
      result = homes_collection.find_one_and_update({"created_by":user_id},{"$set":{"url":url}})
      if result==None:
         return jsonify({"Error":"Homes doesnt exist"})
      else:
        return jsonify({"Message":"Successfully updated"})
   
   except Exception as e:
 
      print("Error",e)
      return jsonify({"Error":e})
     

@app.route('/image/delete',methods=['put'])
@jwt_required()
def updateImg():
   try:
     
      current_user=json.loads(get_jwt_identity()) 
      createdBy=current_user['userId']
 
      result  = homes_collection.find_one_and_update({"created_by":createdBy},{"$set":{"url":"images/defaultImg.png"}})
      if result:
         return jsonify({"Message":"updated"})
      else:
         return jsonify({"error":"invalid home "})
 
      # if result == None:
      #    return jsonify({"error":"invalid home "})
      # else:
      #  return jsonify({"Message":"updated"})
   except Exception as err:
      return jsonify({"error":err})
   
@app.route('/househelp/delete',methods=['DELETE'])
@jwt_required()
def delete_househelp():
    try:
        data=request.json
        househelp_id = data.get('househelp_id')
        print(type(househelp_id))
        if not househelp_id:
            return jsonify({'error':"invalid househelp_id"})
        response = househelps_collection.find_one_and_delete({'_id':ObjectId(househelp_id)})
        print("resssss",response)
        if response:
         return jsonify({'message':'Maid deleted successfully'})
        else:
            return jsonify({'error':'invalid maid'})
    except TypeError as t:
        return jsonify({'type error':t})    
    except ValueError as e:
        return jsonify({'error':e})    
    except Exception as e:
        return jsonify({'error':e})


@app.route('/househelp/updatePaymentDate', methods=['PATCH'])
def update_payment_date():
    try:

        data = request.json
        househelp_id = data.get('househelp_id')
        print(househelp_id)
        househelp = househelps_collection.find_one({"_id": ObjectId(househelp_id)})
        if not househelp:
            return jsonify({"error": "Househelp not found"}), 404

        payment_type = househelp['financial_info'].get('payment_type')
        current_payment_date = househelp['financial_info'].get('payment_date')

        if not payment_type or not current_payment_date:
            return jsonify({"error": "Payment type or payment date is missing"}), 400

        current_payment_date = datetime.datetime.strptime(current_payment_date, '%Y-%m-%d')

   
        if payment_type == 'Daily':
            new_payment_date = current_payment_date + timedelta(days=1)
        elif payment_type == 'Weekly':
            new_payment_date = current_payment_date + timedelta(weeks=1)
        elif payment_type == 'Monthly':
            new_payment_date = current_payment_date + timedelta(days=30)  # Approximation
        elif payment_type == 'Yearly':
            new_payment_date = current_payment_date + timedelta(days=365)
        else:
            return jsonify({"error": "Invalid payment type"}), 400

        househelps_collection.update_one(
            {"_id": ObjectId(househelp_id)},
            {"$set": {"financial_info.payment_date": new_payment_date.strftime('%Y-%m-%d')}}
        )

        return jsonify({
            "message": "Payment date updated successfully",
            "new_payment_date": new_payment_date.strftime('%Y-%m-%d')
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/househelp/cat', methods=['GET'])
@jwt_required()
def get_cat():
    try:
   
        current_user = json.loads(get_jwt_identity()) 
        home_id = current_user['homeId']


        househelps = list(househelps_collection.find({'homeId': home_id}, {'category_id': 1}))

        if not househelps:
            return jsonify({'error': 'No househelp found'}), 404

        unique_categories = {}

        for househelp in househelps:
            category = categories_collection.find_one({'_id': ObjectId(househelp['category_id'])}, {'_id': 1, 'category_name': 1})

            if category:
             
                unique_categories[str(category['_id'])] = {
                    '_id': str(category['_id']),
                    'category_name': category['category_name']
                }
        unique_category_list = list(unique_categories.values())

        return jsonify({'categories': unique_category_list}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/gas_consumption/monthly_days', methods=['GET'])
@jwt_required()
def get_monthly_days_consumption():
    try:
        
        current_user = json.loads(get_jwt_identity()) 
        homeId = current_user['homeId']

        records = gas_collection.find({"homeId": homeId}).sort("delivered_date", 1).limit(4)


        records_list = [{**record, "_id": str(record["_id"])} for record in records]

        if not records_list:
            return jsonify({"error": "No gas consumption records found"}), 404

        monthly_days = []
        for i in range(len(records_list) - 1):
            current_date = records_list[i]['delivered_date']
            next_date = records_list[i + 1]['delivered_date']

      
            days_consumed = (next_date - current_date).days

            monthly_days.append({
                "month": current_date.strftime('%B'), 
                "days_consumed": days_consumed,
                "start_date": current_date.strftime('%Y-%m-%d'),
                "end_date": next_date.strftime('%Y-%m-%d')
            })

  
        if records_list:
            last_date = records_list[-1]['delivered_date']
            current_date = datetime.datetime.now()

            last_month_days = (current_date - last_date).days
            monthly_days.append({
                "month": last_date.strftime('%B'),
                "days_consumed": last_month_days,
                "start_date": last_date.strftime('%Y-%m-%d'),
                "end_date": "Ongoing"
            })

        return jsonify(monthly_days), 200

    except Exception as e:
        return jsonify({"error": "Failed to calculate monthly days consumption", "message": str(e)}), 500


@app.route('/warranties/addData', methods=['POST'])
@jwt_required()
def add_warranty_data():
    try:
        data = request.json
        current_user = json.loads(get_jwt_identity()) 

        user_id = current_user['userId']
        homeId = current_user['homeId']
        data['createdBy'] = str(user_id)
        data['homeId'] = homeId
        record = {
            "purchase_date": datetime.datetime.strptime(data.get("purchase_date"), '%Y-%m-%d'),
            "product_name": data.get("product_name"),
            "product_type": data.get("product_type"),
            "brand": data.get("brand"),
            "price": data.get("price"),
            "warranty": data.get("warranty"),
            "createdBy": data['createdBy'],
            "homeId": data['homeId']
        }

        result = warranties.insert_one(record)
        record['_id'] = str(result.inserted_id)

        return jsonify({"message": "warranty added successfully!", "data": record}), 201

    except Exception as e:
        return jsonify({"error": "Failed to add warranty record", "message": str(e)}), 400


@app.route('/warranties/getData', methods=['GET'])
@jwt_required()
def get_all_warranty_data():
    try:
       
        current_user = json.loads(get_jwt_identity()) 
        user_id = current_user['userId']
        home_id = current_user['homeId']

        records = warranties.find({"createdBy": user_id, "homeId": home_id})

        warranty_list = []
        for record in records:
            warranty_data = {
                "_id": str(record["_id"]),
                "purchase_date": record.get("purchase_date").strftime('%Y-%m-%d') if record.get("purchase_date") else None,
                "product_name": record.get("product_name"),
                "product_type": record.get("product_type"),
                "brand": record.get("brand"),
                "price": record.get("price"),
                "warranty": record.get("warranty"),
                "createdBy": record.get("createdBy"),
                "homeId": record.get("homeId")
            }
            warranty_list.append(warranty_data)


        return jsonify({"message": "Warranty records fetched successfully", "data": warranty_list}), 200

    except Exception as e:
        return jsonify({"error": "Failed to fetch warranty records", "message": str(e)}), 400

@app.route('/warranties/delete',methods=['DELETE'])
@jwt_required()
def warranties_delete():
    try:
        data = request.json
        product_id = data['product_id']
        current_user = json.loads(get_jwt_identity()) 
        userId= current_user['userId']
        homeId = current_user['homeId']

        result = warranties.find_one_and_delete({'_id':ObjectId(product_id),"createdBy":userId,'homeId':homeId})
        if result :
            return jsonify({"message":"deleted successfully"}),200
        else:
            return jsonify({'error':"no warranty found"})
    except Exception as e:
        return jsonify({f'error':"errror in deleting warranty record,{e}"})


@app.route('/newspaper/add', methods=['POST'])
@jwt_required()
def add_newspaper_data():
    try:
        current_user = json.loads(get_jwt_identity()) 
        user_id = current_user['userId']
        homeId = current_user['homeId']

        data = request.get_json()
        newspaper_name = data.get("newspaper_name")
        bill_date = data.get("bill_date")
        amount = data.get("amount")

        if not newspaper_name or not bill_date or not amount:
            return jsonify({"error": "Missing required fields"}), 400

        bill_date = datetime.datetime.strptime(bill_date, '%Y-%m-%d')

    
        newspaper.insert_one({
            "newspaper_name": newspaper_name,
            "bill_date": bill_date,
            "amount": amount,
            "createdBy": user_id,
            "homeId":homeId
        })

        return jsonify({"message": "Newspaper data added successfully"}), 201

    except Exception as e:
        return jsonify({"error": "Failed to add newspaper data", "message": str(e)}), 400


@app.route('/newspaper/last_three_months', methods=['GET'])
@jwt_required()
def get_last_three_months_data():
    try:
        current_user = json.loads(get_jwt_identity()) 
        homeId = current_user['homeId']

        three_months_ago = datetime.datetime.now() - timedelta(days=90)


        records = newspaper.find({
            "homeId":homeId,
            "bill_date": {"$gte": three_months_ago}
        })

        newspaper_list = []
        for record in records:
            newspaper_data = {
                "_id": str(record["_id"]),
                "newspaper_name": record.get("newspaper_name"),
                "bill_date": record.get("bill_date").strftime('%Y-%m-%d') if record.get("bill_date") else None,
                "amount": record.get("amount"),
                "createdBy": record.get("createdBy")
            }
            newspaper_list.append(newspaper_data)

        return jsonify({"message": "Last 3 months' data fetched successfully", "data": newspaper_list}), 200

    except Exception as e:
        return jsonify({"error": "Failed to fetch newspaper data", "message": str(e)}), 400

# def lambda_handler(event, context):
#     return handle_request(app, event, context)


if __name__ == '__main__':
    app.run(host="0.0.0.0",debug=True,port=5052)