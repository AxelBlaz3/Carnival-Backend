from flask_pymongo import PyMongo
from bson import json_util
import json

mongo = PyMongo()

def insert():
    pass


def update(filter, update):
    return mongo.db.users.update_one(filter=filter, update=update, upsert=True)


def find(criteria):
    return json.loads(json_util.dumps(mongo.db.users.find_one(criteria)))    