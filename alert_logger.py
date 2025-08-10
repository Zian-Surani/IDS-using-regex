def log_alert(method, payload):
    import os
    os.makedirs('logs', exist_ok=True)
    with open('logs/alerts.log', 'a', encoding='utf-8') as f:
        f.write(f"[{method}] {payload[:200]}\n")
