import traceback
import aiohttp
from bson import json_util
from spotify_request_api import fetch_shows
from threading import Thread
from tmdb_api_request import fetch_movies_async, fetch_tv_async

from flask import Blueprint, json, request, jsonify, render_template, copy_current_request_context, current_app
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, create_refresh_token, get_jwt_identity
from flask_bcrypt import Bcrypt, check_password_hash, generate_password_hash
from bson.objectid import ObjectId
from db import mongo
from flask_mail import Mail, Message
import random
import string

api_v1 = Blueprint('api_v1', __name__)
jwt = JWTManager()
bcrypt = Bcrypt()
mail = Mail()


@api_v1.route('/login', methods=['POST'])
def login():
    email = request.json['email']
    password = request.json['password']

    if len(email) == 0 or len(password) == 0:
        return jsonify(error='Email or password cannot be empty'), 400

    users_collection = mongo.db.users
    user = users_collection.find_one_or_404(
        {'email': email})

    is_password_matched = bcrypt.check_password_hash(
        pw_hash=user['password'], password=password)
    if not is_password_matched:
        return jsonify(error='Invalid credentials provided'), 403

    access_token = create_access_token(identity=str(user['_id']))
    refresh_token = create_refresh_token(identity=str(user['_id']))
    user_json = json.loads(json_util.dumps(user))

    user_json['access_token'] = access_token
    user_json['refresh_token'] = refresh_token
    user_json['access_token_expires_in']=current_app.config['JWT_ACCESS_TOKEN_EXPIRES'].seconds // 3600
    user_json['refresh_token_expires_in']=current_app.config['JWT_REFRESH_TOKEN_EXPIRES'].days
    del user_json['password']

    _id = user_json['_id']['$oid']
    user_json['_id'] = _id

    return jsonify(user_json)


@api_v1.route('/signup', methods=['POST'])
def signup():
    email = request.json['email']
    password = request.json['password']

    if email is None or password is None or len(email) == 0 or len(password) == 0:
        return jsonify(error='Email or password cannot be empty'), 401

    users_collection = mongo.db.users
    credentials = {'email': email,
                   'password': bcrypt.generate_password_hash(password=password)}
    user = users_collection.find_one({'email': email})
    if user is not None:
        return jsonify(error='User already exists'), 409
    result = users_collection.insert_one(credentials)
    user = users_collection.find_one({'_id': result.inserted_id})

    access_token = create_access_token(identity=str(user['_id']))
    refresh_token = create_refresh_token(identity=str(user['_id']))
    user_json = {'_id': str(user['_id']), 'email': user['email'],
                 'access_token': access_token, 'refresh_token': refresh_token, 'access_token_expires_in': current_app.config['JWT_ACCESS_TOKEN_EXPIRES'].seconds // 3600}
    return jsonify(user_json), 201


@api_v1.route('/user/<_id>', methods=['PUT'])
@jwt_required()
def update(_id):
    users_collection = mongo.db.users
    update_filter = {'_id': ObjectId(_id)}
    update_dict = request.json

    is_favorite = update_dict['is_favorite']
    del update_dict['is_favorite']
    if is_favorite is not None and is_favorite is True:
        movie = None
        tv = None
        podcast = None
        if 'movie' in update_dict:
            movie = update_dict['movie']
        if 'show' in update_dict:
            tv = update_dict['show']
        if 'podcast' in update_dict:
            podcast = update_dict['podcast']

        if movie is not None:
            if movie['favorite'] is True:
                updated_user = {'$addToSet': {'favorites.movies': movie}}
            else:
                updated_user = {
                    '$pull': {'favorites.movies': {'id': movie['id']}}}
        elif tv is not None:
            if tv['favorite'] is True:
                updated_user = {'$addToSet': {'favorites.shows': tv}}
            else:
                updated_user = {'$pull': {'favorites.shows': {'id': tv['id']}}}
        elif podcast is not None:
            if podcast['favorite'] is True:
                updated_user = {'$addToSet': {'favorites.podcasts': podcast}}
            else:
                updated_user = {
                    '$pull': {'favorites.podcasts': {'id': podcast['id']}}}
        else:
            return jsonify(status=False, message='Provide an update category.'), 400
        update_result = users_collection.update_one(
            filter=update_filter, update=updated_user, upsert=True)
        if update_result.modified_count > 0:
            return jsonify(status=True, message='User preferences updated.'), 200
        return jsonify(status=False, message='Some error occured.'), 403

    try:
        del update_dict['email']
        del update_dict['_id']
    except KeyError:
        traceback.print_exc()

    updated_user = {'$set': update_dict}
    update_result = users_collection.update_one(
        filter=update_filter, update=updated_user, upsert=True)
    if update_result.modified_count > 0:
        return jsonify(status=True, message='User preferences updated.'), 200
    return jsonify(status=False, message='Some error occured.'), 403


@api_v1.route('/email/<email_id>/send', methods=['POST'])
def send_email(email_id):
    if email_id is None or len(email_id) == 0:
        return jsonify(status=False, message='Invalid email'), 400

    filter_criteria = {'email': email_id}
    user = mongo.db.users.find_one(filter=filter_criteria)

    if user is None:
        return jsonify(status=False, message='No account exists with the email.'), 404

    pass_length = 10
    random_password = ''.join(random.choices(
        string.ascii_uppercase + string.digits, k=pass_length))

    # Insert or update random_password in db.
    update_filter = {'_id': ObjectId(user['_id'])}
    updated_user = {
        '$set': {'random_password': generate_password_hash(random_password)}}
    update_result = mongo.db.users.update_one(
        filter=update_filter, update=updated_user, upsert=True)
    if update_result.modified_count <= 0:
        return jsonify(status=False, message='Password update failed.'), 400

    sender = 'wielabstest@gmail.com'
    subject = 'Reset your password'

    @copy_current_request_context
    def send_mail(mail):
        try:
            html_content = render_template(
                'email/email_template.html', random_password=random_password)
            message = Message(subject=subject, html=html_content,
                              sender=sender, recipients=[email_id])
            mail.send(message=message)
        except:
            pass

    mail_thread = Thread(target=send_mail, args=[mail])
    mail_thread.start()
    return jsonify(message='Mail has been sent successfully.', status=True), 200


@api_v1.route('/user/<email_id>/password/reset', methods=['PUT'])
def reset_password(email_id):
    credentials = request.json

    if email_id is None or len(str(email_id)) <= 0:
        return jsonify(status=False, message='Invalid email address provided.'), 400
    if credentials['random_password'] is None:
        return jsonify(status=False, message='Provide a random password that you received via email client.'), 400
    if credentials['new_password'] is None:
        return jsonify(status=False, message='You must provide a new password.'), 400

    filter_criteria = {'email': email_id}
    users_collection = mongo.db.users
    user = users_collection.find_one(filter=filter_criteria)

    if user is None:
        return jsonify(status=False, message='That email does not exist'), 404

    if not check_password_hash(pw_hash=user['random_password'], password=credentials['random_password']):
        return jsonify(status=False, message='Incorrect random password provided.'), 403

    update_dict = {'password': generate_password_hash(
        credentials['new_password'])}
    update_filter = {'_id': user['_id']}
    updated_user = {'$set': update_dict}
    update_result = users_collection.update_one(
        filter=update_filter, update=updated_user)
    if update_result.modified_count > 0:
        return jsonify(status=True, message='Password updated successfully.'), 200
    return jsonify(status=False, message='Some error occured'), 403


@api_v1.route('/movies')
async def get_movies():

    page = request.args.get('page', '')
    workout_length = request.args.get('workout_length', '')
    genres = request.args.get('genres', '')
    without_genres = request.args.get('without_genres', None)
    watch_providers = request.args.get('watch_providers', '')
    watch_region = request.args.get('watch_region', '')

    if page is None or not str(page).isnumeric or int(page) < 1 or int(page) > 3:
        return jsonify(status=False, message='Page must be in the range 1-3.'), 400

    if workout_length is None or not workout_length:
        return jsonify(status=False, message='Workout length isn\'t provided.'), 400

    if genres is None or not genres:
        return jsonify(status=False, message='Genres cannot be empty.'), 400

    if watch_providers is None or not watch_providers:
        return jsonify(status=False, message='Watch providers cannot be empty.'), 400

    if watch_region is None or not watch_region:
        return jsonify(status=False, message='Watch region isn\'t provided.'), 400

    return jsonify(await fetch_movies_async(page=page, without_genres=without_genres, genres=genres, watch_providers=watch_providers, watch_region=watch_region))


@api_v1.route('/tv')
async def get_tv():

    page = request.args.get('page', '')
    workout_length = request.args.get('workout_length', '')
    genres = request.args.get('genres', '')
    without_genres = request.args.get('without_genres', None)
    watch_providers = request.args.get('watch_providers', '')
    watch_region = request.args.get('watch_region', '')

    if page is None or not str(page).isnumeric or int(page) < 1 or int(page) > 3:
        return jsonify(status=False, message='Page must be in the range 1-3.'), 400

    if workout_length is None or not workout_length:
        return jsonify(status=False, message='Workout length isn\'t provided.'), 400

    if genres is None or not genres:
        return jsonify(status=False, message='Genres cannot be empty.'), 400

    if watch_providers is None or not watch_providers:
        return jsonify(status=False, message='Watch providers cannot be empty.'), 400

    if watch_region is None or not watch_region:
        return jsonify(status=False, message='Watch region isn\'t provided.'), 400

    return jsonify(await fetch_tv_async(workout_length=workout_length, page=page, without_genres=without_genres, genres=genres, watch_providers=watch_providers, watch_region=watch_region))


@api_v1.route('/podcasts/<podcast_ids>')
async def get_podcasts(podcast_ids):
    region = request.args.get('region', None)

    if region is None:
        return jsonify(status=False, message='Region must be provided'), 400

    async with aiohttp.ClientSession() as session:
        return jsonify(await fetch_shows(podcast_ids=podcast_ids.split(','), region=region, client_session=session))


@api_v1.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    identity = get_jwt_identity()
    access_token = create_access_token(identity=identity, fresh=False)
    return jsonify(access_token=access_token, access_token_expires_in=current_app.config['JWT_ACCESS_TOKEN_EXPIRES'].seconds // 3600)
