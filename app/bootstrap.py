from app.db import get_supabase_client

def ensure_root_user():
    supabase = get_supabase_client()
    try:
        # Check if any users exist
        response = supabase.table('users').select('id').limit(1).execute()
        if not response.data:
            print("No users found. Creating temporary root user...")

            # Create auth user with metadata
            user_metadata = {
                "full_name": "Root User",
                "privilege": "admin",
                "theme": "light",
                "otp_expires_at": None,
                "created_by": "system"
            }

            create_resp = supabase.auth.admin.create_user({
                "email": "root@local",
                "password": "root",
                "email_confirm": True,
                "user_metadata": user_metadata
            })

            auth_user = getattr(create_resp, "user", None) or (create_resp.get("user") if isinstance(create_resp, dict) else None)
            if not auth_user:
                print("Failed to create root user in Supabase Auth.")
                return

            # Insert flags into users table
            supabase.table('users').insert({
                "id": auth_user.id,
                "requires_password_change": True,
                "support_allowed": False,
                "privilege": "admin"
            }).execute()

            print("Temporary 'root' user added (admin, requires password change).")

    except Exception as e:
        print(f"Error ensuring root user exists: {e}")