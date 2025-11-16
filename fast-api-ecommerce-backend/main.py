from auth.models import UserCreate, UserLogin
from fastapi import FastAPI, HTTPException
from database import users_collection
from auth.auth import hash_password, verify_password, create_access_token

app = FastAPI()


@app.get("/")
async def root():
    return {"message": "Hello World"}


@app.get("/hello/{name}")
async def say_hello(name: str):
    return {"message": f"Hello {name}"}

# -----------------------
#  REGISTER ENDPOINT
# -----------------------
@app.post("/register")
async def register(user: UserCreate):
    existing_user = await users_collection.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_pw = hash_password(user.password)
    new_user = {
        "email": user.email,
        "password": hashed_pw
    }

    await users_collection.insert_one(new_user)

    return {"message": "User created successfully"}

# -----------------------
#  LOGIN ENDPOINT
# -----------------------
@app.post("/login")
async def login(user: UserLogin):
    db_user = await users_collection.find_one({"email": user.email})

    if not db_user:
        raise HTTPException(status_code=400, detail="Invalid email or password")

    if not verify_password(user.password, db_user["password"]):
        raise HTTPException(status_code=400, detail="Invalid email or password")

    token = create_access_token({"sub": user.email})

    return {"access_token": token, "token_type": "bearer"}