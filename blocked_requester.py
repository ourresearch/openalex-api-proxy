import datetime

from sqlalchemy import Sequence

from app import db


class BlockedRequester(db.Model):
    __tablename__ = "blocked_requester"

    id = db.Column(db.BigInteger, Sequence('blocked_requester_id_seq', start=1, increment=1), primary_key=True)
    ip = db.Column(db.Text, nullable=False, unique=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.datetime.now(datetime.timezone.utc).isoformat())
    active = db.Column(db.Boolean, nullable=False, default=True)
    notes = db.Column(db.Text)

    def to_dict(self):
        return {
            'ip': self.ip,
            'created': self.created,
            'active': self.active,
            'notes': self.notes
        }

    def __repr__(self):
        return f'<BlockedRequester ({self.ip})>'


_blocked_requesters_by_ip = {}

for blocked_requester in BlockedRequester.query.filter_by(active=True):
    _blocked_requesters_by_ip[blocked_requester.ip] = blocked_requester


def check_for_blocked_requester(request_ip):
    return _blocked_requesters_by_ip.get(request_ip)
