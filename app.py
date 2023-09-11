from flask import Flask, jsonify, request, send_file,Response
from pymongo import MongoClient
from pymongo import ASCENDING, DESCENDING
from bson import ObjectId
from flask_cors import CORS
from werkzeug.utils import secure_filename
import bcrypt
import os
import io
from gridfs import GridFS
from dotenv import load_dotenv
from flask_jwt_extended import create_access_token, JWTManager, jwt_required, get_jwt_identity

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'your_secret_key' 
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'
jwt = JWTManager(app)

# Explicitly load the .env file
dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path)

mongo_uri = os.environ.get('API_URL')

client = MongoClient(mongo_uri)  
db = client['mydatabase']
userCollection = db['users']
clinteUserCollection = db['clinteUsers']
pdf_collection = db["pdf_collection"]

UPLOAD_FOLDER = 'uploads'  
ALLOWED_EXTENSIONS = {'pdf'}  

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Function to check if a filename has a valid extension
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# route for downloading file
pdf_fs = GridFS(db, collection='pdf_collection')

@app.route('/download_pdf/<pdf_id>', methods=['GET'])
def download_pdf(pdf_id):
    try:
        pdf_document = pdf_collection.find_one({'_id': ObjectId(pdf_id)})

        if pdf_document:
            pdf_data = pdf_document["pdf_data"]
            filename = pdf_document["filename"]
            response = Response(io.BytesIO(pdf_data))
            response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
            return response
        else:
            return 'PDF not found', 404

    except Exception as e:
        print(str(e))
        return 'Internal Server Error', 500

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
        with open(os.path.join(app.config['UPLOAD_FOLDER'], filename), 'rb') as pdf_file:
            pdf_data = pdf_file.read()
            pdf_collection.insert_one({'filename': filename, 'pdf_data': pdf_data})

        return jsonify({'message': 'File uploaded successfully'})

    return jsonify({'error': 'Invalid file type'})

# Route for adding operator data
@app.route('/users', methods=['POST'])
def add_user():
    data = request.get_json()

    password = data['password']
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=5))
    data['password'] = hashed_password.decode('utf-8')
    
    document = data

    result = userCollection.insert_one(document)

    return jsonify({'id': str(result.inserted_id)})

# Route for operator login 
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['email']
    password = data['password']
 
    user = userCollection.find_one({'email': username})
    
    if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        access_token = create_access_token(identity=str(user['_id']))
        
        return jsonify({'access_token': access_token})
    
    return jsonify({'message': 'Invalid username or password'}), 401

# Route for signup clinte user
@app.route('/clintesignup', methods=['POST'])
def add_clinteuser():
    data = request.get_json()

    password = data['password']
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=5))
    data['password'] = hashed_password.decode('utf-8')
    
    document = data

    result = clinteUserCollection.insert_one(document)

    return jsonify({'id': str(result.inserted_id)})

# Route for login clinte user
@app.route('/clintelogin', methods=['POST'])
def clintelogin():
    data = request.get_json()
    username = data['email']
    password = data['password']
 
    user = clinteUserCollection.find_one({'email': username})
    
    if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        access_token = create_access_token(identity=str(user['_id']))
        
        return jsonify({'access_token': access_token})
    
    return jsonify({'message': 'Invalid username or password'}), 401

# route for getting all files
@app.route('/get_pdf_data', methods=['GET'])
def get_pdf_data():
    pdf_data = list(pdf_collection.find())

    pdf_list = []
    for items in pdf_data:
        pdf_list.append({
            'id': str(items['_id']),
            'filename': items['filename'],
        })

    return jsonify(pdf_list)

if __name__ == '__main__':
    app.run(port=11000)
