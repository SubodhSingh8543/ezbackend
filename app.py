from flask import Flask, jsonify, request
from pymongo import MongoClient
from pymongo import ASCENDING, DESCENDING
from bson import ObjectId
from bson import ObjectId
from flask_cors import CORS
import bcrypt
from jwt import DecodeError
import os
# DecodeError
from dotenv import load_dotenv
from flask_jwt_extended import create_access_token, JWTManager, jwt_required, get_jwt_identity

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'your_secret_key'  # Replace with a strong secret key
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'  # Replace with another strong secret key
jwt = JWTManager(app)

# Explicitly load the .env file
dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path)

mongo_uri = os.environ.get('API_URL')
# mongo_uri = "mongodb+srv://subodhsingh8543:ezproject@cluster0.xybezni.mongodb.net/?retryWrites=true&w=majority"


client = MongoClient(mongo_uri)  # Use the correct variable here
db = client['mydatabase']
userCollection = db['users']

from werkzeug.utils import secure_filename
import os

UPLOAD_FOLDER = 'uploads'  # Define a folder to store uploaded files
ALLOWED_EXTENSIONS = {'pdf'}  # Define allowed file extensions

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Function to check if a filename has a valid extension
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Route for uploading a PDF file
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'})

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No selected file'})

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        # Save file to MongoDB
        with open(os.path.join(app.config['UPLOAD_FOLDER'], filename), 'rb') as pdf_file:
            pdf_data = pdf_file.read()
            db.pdf_collection.insert_one({'filename': filename, 'pdf_data': pdf_data})

        return jsonify({'message': 'File uploaded successfully'})

    return jsonify({'error': 'Invalid file type'})



# upload data
# @app.route('/upload', methods=['POST'])
# @jwt_required()
# def add_data():
#     user_id = get_jwt_identity()
#     return jsonify({'id': user_id})


# Route for adding data
@app.route('/users', methods=['POST'])
def add_user():
    data = request.get_json()

    password = data['password']
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=5))
    data['password'] = hashed_password.decode('utf-8')
    
    document = data

    result = userCollection.insert_one(document)

    return jsonify({'id': str(result.inserted_id)})

# Route for user login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['email']
    password = data['password']

    # Retrieve the user document from the database based on the provided username
    user = userCollection.find_one({'email': username})
    
    if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        # If the username and password are valid, generate a JWT token
        access_token = create_access_token(identity=str(user['_id']))
        
        return jsonify({'access_token': access_token})
    
    return jsonify({'message': 'Invalid username or password'}), 401

if __name__ == '__main__':
    app.run(port=11000)
