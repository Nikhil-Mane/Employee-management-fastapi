from pymongo import MongoClient

MONGO_URI = "mongodb://localhost:80"
client = MongoClient(MONGO_URI)
database = client["mydatabase"]
collection = database["items"]

# Dependency function to get the collection
def get_db():
    return collection
