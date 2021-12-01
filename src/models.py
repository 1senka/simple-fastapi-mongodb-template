from typing import Optional
from mongoengine import Document
from mongoengine.fields import StringField,IntField
from pydantic import BaseModel
class User (BaseModel):
    username:str
    first_name:str
    last_name:str
    email:str
    password:str
    national_id:str
class Product(BaseModel):
    name:str
    price:str
    description:Optional[str]
    
class Token(BaseModel):
    access_token: str
    token_type: str
class MongoUser(Document):
    username=StringField()
    first_name=StringField()
    last_name=StringField()
    email=StringField()
    password=StringField()
    national_id=StringField()
    
class MongoProduct(Document):
    name=StringField()
    price=StringField()
    description= StringField()
    
class TokenData(BaseModel):
    username: Optional[str] = None

