import datetime

class BlockedRequester:
    def __init__(self, ip, created=None, active=True, notes=None):
        self.ip = ip
        self.created = created or datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.active = active
        self.notes = notes

    def to_dict(self):
        return {
            'ip': self.ip,
            'created': self.created,
            'active': self.active,
            'notes': self.notes
        }

    def __repr__(self):
        return f'<BlockedRequester ({self.ip})>'


# Mock blocked requesters data
_blocked_requesters_by_ip = {
    # Example blocked IPs - you can add more as needed
    # '1.2.3.4': BlockedRequester('1.2.3.4', notes='Excessive requests'),
}


def check_for_blocked_requester(request_ip):
    return _blocked_requesters_by_ip.get(request_ip)
