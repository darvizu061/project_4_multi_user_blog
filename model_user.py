from google.appengine.ext import ndb


class User(ndb.Model):
    user_name = ndb.StringProperty(required=True)
    user_password_hash = ndb.TextProperty(required=True)

    @classmethod
    def by_name(cls, name):
        user = User.query(User.user_name == name).fetch(1)
        for u in user:
            return u

    @classmethod
    def by_id(cls, user_id):
        return User.get_by_id(int(user_id))

    @classmethod
    def by_name_and_pw(cls, name, password_hash):
        user = User.query(User.user_name == name).fetch(1)
        for u in user:
            if u.user_password_hash == password_hash:
                return u
            else:
                return False

    @classmethod
    def get_user_id(cls, user):
        return user.key.id()

    @classmethod
    def register_user(cls, name, password_hash):
        u = User(user_name=name, user_password_hash=password_hash)
        u.put()
        return u.key.id()
