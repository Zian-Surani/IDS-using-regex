def extract_payload(packet):
    if hasattr(packet, 'load'):
        try:
            return packet.load.decode('utf-8', errors='ignore')
        except:
            return str(packet.load)
    return ''
