from app.db import get_supabase_client

def ensure_root_user():
    supabase = get_supabase_client()
    try:
        # Check if any users exist
        response = supabase.table('users').select('id').limit(1).execute()
        if not response.data:
            print("No users found. Creating temporary root user...")

            # Create auth user
            auth_user = supabase.auth.admin.create_user({
                "email": "root@local",
                "password": "root",
                "email_confirm": True
            }).user

            if not auth_user:
                print("Failed to create root user in Supabase Auth.")
                return

            # Insert user data
            supabase.table('users').insert({
                "id": auth_user.id,
                "username": "root@local",
                "privilege": "admin",
                "requires_password_change": True,
                "name": "Root User",
                "support_allowed": False
            }).execute()

            print("✅ Temporary 'root' user added (admin, requires password change).")

    except Exception as e:
        print(f"❌ Error ensuring root user exists: {e}")