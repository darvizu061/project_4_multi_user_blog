from google.appengine.ext import ndb


class LikePost(ndb.Model):
    like_post = ndb.StringProperty(required=True)
    like_author = ndb.StringProperty(required=True)
    like_create = ndb.DateTimeProperty(auto_now_add=True)

    @classmethod
    def add_like(cls, post_id, author):
        l = LikePost(like_post=str(post_id),
                     like_author=str(author))
        l.put()
        return l.key.id()

    @classmethod
    def by_post_and_author(cls, post_id, author):
        likes = LikePost.query(LikePost.like_post == post_id and
                               LikePost.like_author == author).fetch(1)
        for l in likes:
            return l

    @classmethod
    def delete_like(cls, like_id):
        like = LikePost.get_by_id(int(like_id))
        if like:
            like.key.delete()
            return True
        else:
            return False
