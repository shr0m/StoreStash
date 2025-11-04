from datetime import datetime
from flask import session
from app import get_supabase_client  # adjust import to your structure

def log_audit_action(client_id, user_id, action, description):
    try:
        supabase = get_supabase_client()
        log_entry = {
            'client_id': client_id,
            'user_id': user_id,
            'timestamp': datetime.utcnow().isoformat(),
            'action': action,
            'description': description,
        }

        supabase.table('audit_log').insert(log_entry).execute()
    except Exception as e:
        print(f"[Audit Log Error] {e}")