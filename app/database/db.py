from pymongo import MongoClient

MONGO_URI = "mongodb://localhost:27008"
client = MongoClient(MONGO_URI)
database = client["mydatabase"]

# Dependency function to get the database connection
def get_db():
    return database  # Return the entire database
