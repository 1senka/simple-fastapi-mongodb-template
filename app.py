from datetime import datetime, timedelta
from os import name
from fastapi import APIRouter, Depends, HTTPException, Query, status, FastAPI, HTTPException
from fastapi.param_functions import Security
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import json
from jose import jwt, JWTError
from src.models import *
from mongoengine import connect, disconnect
import re
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

origins = [
    "*",

]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
user_router = APIRouter(
    prefix="/users",
    tags=["users"],
    responses={404: {"description": "Not found"}}
)
product_router = APIRouter(
    prefix="/products",
    tags=["products"],
    responses={404: {"description": "Not found"}})

email_expression = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
password_expression = r"^(?=.*[\d])(?=.*[A-Z])(?=.*[a-z])(?=.*[@#$])[\w\d@#$]{6,12}$"

crypt_context = CryptContext(schemes=["sha256_crypt", "md5_crypt"])


def get_password_hash(password):
    return crypt_context.hash(password)


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token", auto_error=False)


@user_router.post("/signup")
async def sign_up(newUser: User):
    user = MongoUser(username=newUser.username,
                     password=get_password_hash(newUser.password),
                     first_name=newUser.first_name,
                     last_name=newUser.last_name,
                     email=newUser.email,
                     national_id=newUser.national_id)
    if(check_user(user)):
        user.save()
        return {"message": "user created"}
    else:
        return {"message": "wrong inputs"}


SECRET_KEY = "3e8a3f31aab886f8793176988f8298c9265f84b8388c9fef93635b08951f379b"


def check_user(user: User):
    res = True
    if(re.search(user.email, email_expression) == None):
        res = False
    if(re.search(user.password, password_expression) == None):
        res = False
    if((user.password.isnumeric() == False) or len(user.password) != 9):
        res = False
    return res


def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")
    return encoded_jwt


def authenticate(username, password):
    try:
        user = get_user(username)
        password_check = crypt_context.verify(password, user['password'])
        return password_check
    except User.DoesNotExist:
        return False


@user_router.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    username = form_data.username
    password = form_data.password
    if authenticate(username, password):
        access_token = create_access_token(
            data={"sub": username}, expires_delta=timedelta(minutes=20))
        return {"access_token": access_token, "token_type": "bearer"}
    else:
        raise HTTPException(
            status_code=400, detail="incorrect username or password")


def get_user(username: str):
    try:
        user = json.loads(MongoUser.objects.get(username=username).to_json())
        return user
    except User.DoesNotExist:
        return None


async def get_current_user(token: str = Security(oauth2_scheme)):
    print(token)
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="wrong cridentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        if (token):
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            username: str = payload.get("sub")
            if username is None:
                raise credentials_exception
            token_data = TokenData(username=username)
            user = get_user(username=token_data.username)
            if (user is None):
                raise credentials_exception
            return user
    except JWTError:
        raise credentials_exception


@product_router.post('/create')
async def create_product(new_product: Product, user=Depends(get_current_user)):
    product = MongoProduct(
        name=new_product.name, price=new_product.price, description=new_product.description)
    if(product):
        product.save()
        return{"message": "saved"}
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="bad request",
        )


@product_router.get('/{name}')
async def read_product(name: str, current_user: User = Depends(get_current_user)):
    product = MongoProduct.objects(name=name)
    if (product):
        return json.loads(product.to_jason())
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="product not found",
        )


@product_router.delete('/{name}')
async def delete_product(name: str):
    product = MongoProduct.objects(name=name)
    if(product):
        product.delete()
        return {"Message": "deleted successfully"}
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="product not found",
        )


@product_router.put('/{name}')
async def update_product(name: str, price: str, current_user: User = Depends(get_current_user)):
    product = MongoProduct.objects(name=name)
    if(product):
        if(price.isnumeric()):
            product.price = price
            product.save()
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="price is not numeric")
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="product not found",
        )

connect(host='mongodb+srv://...(connection string)')


app.include_router(user_router)
app.include_router(product_router)
