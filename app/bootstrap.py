from app.db import get_supabase_client
from app.utils.otp_utils import generate_password_hash

def ensure_root_user():
    supabase = get_supabase_client()
    try:
        # Check if any users exist
        response = supabase.table('users').select('id').limit(1).execute()
        if len(response.data) == 0:
            print("No users found. Inserting temporary 'root' user...")

            defPass = generate_password_hash("root")

            supabase.table('users').insert({
                "username": "root",
                "privilege": "admin",
                "password_hash": defPass,
                "requires_password_change": True,
                "name": "Root User",
            }).execute()

            print("Temporary 'root' user added to users table.")

    except Exception as e:
        print(f"Error ensuring root user exists: {e}")