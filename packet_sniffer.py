# Packet sniffer with fallback demo data if scapy not available or permission denied
def capture_packets(count=5):
    try:
        from scapy.all import sniff
        return sniff(count=count, timeout=10)
    except Exception as e:
        # Fallback: return list of simple objects with .load attribute
        class P:
            def __init__(self, load):
                self.load = load
        demo = [P('normal http get /index.html'), P('<script>alert(1)</script>'), P('select * from users')]
        return demo[:count]
