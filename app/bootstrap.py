from app.db import get_supabase_client
import os

CLIENT_ID = os.getenv("CLIENT_ID")

def ensure_root_user():
    supabase = get_supabase_client()

    if not CLIENT_ID:
        print("No client ID found. Skipping root user creation.")
        return

    try:
        #Get all auth users
        users_resp = supabase.auth.admin.list_users()

        # Handle possible return shapes
        if isinstance(users_resp, list):
            all_users = users_resp
        elif hasattr(users_resp, "users"):
            all_users = users_resp.users
        elif hasattr(users_resp, "data"):
            all_users = users_resp.data
        elif isinstance(users_resp, dict):
            all_users = users_resp.get("users") or users_resp.get("data") or []
        else:
            all_users = []

        #Filter users by client_id stored in user_metadata
        existing_users = [
            u for u in all_users
            if u and getattr(u, "user_metadata", None)
            and u.user_metadata.get("client_id") == CLIENT_ID
        ]

        if existing_users:
            print(f"Users already exist for client_id={CLIENT_ID}, skipping root creation.")
            return

        print(f"No users found for client_id={CLIENT_ID}. Creating temporary root user...")

        user_metadata = {
            "full_name": "Root User",
            "privilege": "admin",
            "theme": "light",
            "otp_expires_at": None,
            "created_by": "system",
            "client_id": CLIENT_ID,
        }

        # Create the root auth user
        create_resp = supabase.auth.admin.create_user({
            "email": f"root@{CLIENT_ID}",
            "password": "root",
            "email_confirm": True,
            "user_metadata": user_metadata,
        })

        # Extract user object safely
        auth_user = getattr(create_resp, "user", None)
        if not auth_user and isinstance(create_resp, dict):
            auth_user = create_resp.get("user")

        if not auth_user:
            print("Failed to create root user in Supabase Auth.")
            return

        # Insert internal record (optional)
        supabase.table("users").insert({
            "id": auth_user.id,
            "requires_password_change": True,
            "support_allowed": False,
        }).execute()

        print(f"Root user created for client_id={CLIENT_ID} root@{CLIENT_ID}.")

    except Exception as e:
        print(f"Error ensuring root user exists: {e}")