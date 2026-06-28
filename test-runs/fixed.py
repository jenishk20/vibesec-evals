from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from typing import Optional
import secrets

app = FastAPI()

users = {}
orders = {}
products = {}
next_user_id = 1
next_order_id = 1
next_product_id = 1
tokens = {}
roles = {}

class SignupRequest(BaseModel):
    username: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

class OrderCreate(BaseModel):
    product: str
    amount: float

class ProductCreate(BaseModel):
    name: str
    price: float

def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="No auth header")
    token = authorization.replace("Bearer ", "")
    if token not in tokens:
        raise HTTPException(status_code=401, detail="Invalid token")
    return tokens[token]

@app.post("/signup")
def signup(req: SignupRequest):
    global next_user_id
    for u in users.values():
        if u["username"] == req.username:
            raise HTTPException(status_code=400, detail="Username exists")
    user_id = next_user_id
    next_user_id += 1
    users[user_id] = {"id": user_id, "username": req.username, "password": req.password}
    roles[user_id] = "user"
    return {"user_id": user_id, "username": req.username}

@app.post("/login")
def login(req: LoginRequest):
    for uid, u in users.items():
        if u["username"] == req.username and u["password"] == req.password:
            token = secrets.token_hex(16)
            tokens[token] = uid
            return {"token": token}
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.post("/promote/{user_id}")
def promote(user_id: int, authorization: Optional[str] = Header(None)):
    admin_id = get_current_user(authorization)
    if roles.get(admin_id) != "admin":
        raise HTTPException(status_code=403, detail="Not admin")
    if user_id not in users:
        raise HTTPException(status_code=404, detail="User not found")
    roles[user_id] = "analyst"
    return {"status": "promoted", "user_id": user_id, "role": "analyst"}

@app.get("/orders/{order_id}")
def get_order(order_id: int, authorization: Optional[str] = Header(None)):
    current_user_id = get_current_user(authorization)
    if order_id not in orders:
        raise HTTPException(status_code=404, detail="Order not found")
    order = orders[order_id]
    # Enforce object-level authorization: only the owner (or an admin)
    # may access an order. Otherwise return 404 to avoid leaking existence.
    if order["user_id"] != current_user_id and roles.get(current_user_id) != "admin":
        raise HTTPException(status_code=404, detail="Order not found")
    return order

@app.get("/products/{product_id}")
def get_product(product_id: int, authorization: Optional[str] = Header(None)):
    get_current_user(authorization)
    if product_id not in products:
        raise HTTPException(status_code=404, detail="Product not found")
    return products[product_id]

@app.post("/orders")
def create_order(order: OrderCreate, authorization: Optional[str] = Header(None)):
    user_id = get_current_user(authorization)
    global next_order_id
    oid = next_order_id
    next_order_id += 1
    orders[oid] = {"id": oid, "user_id": user_id, "product": order.product, "amount": order.amount}
    return orders[oid]

@app.post("/products")
def create_product(product: ProductCreate, authorization: Optional[str] = Header(None)):
    get_current_user(authorization)
    global next_product_id
    pid = next_product_id
    next_product_id += 1
    products[pid] = {"id": pid, "name": product.name, "price": product.price}
    return products[pid]