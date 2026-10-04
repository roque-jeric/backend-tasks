from fastapi import FastAPI, HTTPException, Depends, Header
from jose import jwt, JWTError
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins="*",
    allow_methods="*",
    allow_headers="*"
)

# JWT Config
SECRET_KEY = "mysecret"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# PASSWORD HASHING SETUP
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAUTH SETUP
oauth2_schema = OAuth2PasswordBearer(tokenUrl="login")

# DUMMY USER DB
db = {
    "admin":{
        "hashed_password": pwd_context.hash("1234"),
        "role": "admin"
    },
    "john": {
        "hashed_password": pwd_context.hash("4321"),
        "role": "user"
    }
}

# HASH PASSWORD
def hash_password(password: str):
    return pwd_context.hash(password)

# VERIFY PASSWORD
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# CREATE TOKEN
def create_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({
        "exp": expire
    })
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    
    return token

# TOKEN VERIFICATION
def verify_token(token: str = Depends(oauth2_schema)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=401,
                detail="Invalid Token"
            )
        return {"username": username, **db[username]}
    except jwt.JWTError:
        raise HTTPException(
            status_code=401,
            detail="Invalid Token"
        )
# ROLE CHECKER
def require_role(role: str):
    def checker(user: dict = Depends(verify_token)):
        if user["role"] != role:
            raise HTTPException(status_code=403, detail="Forbidden")
        return user
    return checker

# LOGIN API (OAUTH2 FORM)
@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = db.get(form_data.username)
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=400,
            detail="Invalid username or password"
        )
    access_token = create_token({
        "sub": form_data.username
    })

    return {
        "access_token": access_token,
        "token_type": "bearer"
    }

# PROTECTED ROUTE
@app.get("/protected")
def protected_route(user: dict = Depends(verify_token)):
    return{
        "message": f"Hello {user["username"]}, you have access to this protected route!",
        "user": user["username"]
    }
# ADMIN ROUTE
@app.get("/admin")
def admin_only(user: dict = Depends(require_role("admin"))):
    return {"message": f"Welcome, {user['username']}"}