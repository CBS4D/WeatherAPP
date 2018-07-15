from db import db


class UserModel(db.Model):
    __tablename__ = 'users'

    row_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80))
    password = db.Column(db.String(80))
    organisation_name = db.Column(db.String(80))
    website_url = db.Column(db.String(100))
    subscribe = db.Column(db.Boolean, default=False)

    def __init__(self, username, password,
                 organisation_name, website_url, subscribe=False):
        self.username = username
        self.password = password
        self.organisation_name = organisation_name
        self.website_url = website_url
        self.subscribe = subscribe

    def json(self):
        return {
            'row_id': self.row_id,
            'username': self.username
        }

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    def delete_from_db(self):
        db.session.delete(self)
        db.session.commit()

    def update(self):
        db.session.commit()

    @classmethod
    def find_by_username(cls, username):
        return cls.query.filter_by(username=username).first()

    @classmethod
    def find_by_id(cls, row_id):
        return cls.query.filter_by(row_id=row_id).first()
