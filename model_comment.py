from google.appengine.ext import ndb


class Comment(ndb.Model):
    comment_post = ndb.StringProperty(required=True)
    comment_text = ndb.StringProperty(required=True)
    comment_created = ndb.DateTimeProperty(auto_now_add=True)
    comment_author = ndb.StringProperty(required=True)

    @classmethod
    def by_post_id(cls, post_id):
        return Comment.query(Comment.comment_post == post_id)

    @classmethod
    def get_comment(cls, comment_id):
        return Comment.get_by_id(int(comment_id))

    @classmethod
    def add_comment(cls, post_id, text, author):
        c = Comment(comment_post=str(post_id),
                    comment_text=str(text),
                    comment_author=str(author))
        c.put()
        return c.key.id()

    @classmethod
    def delete_comment(cls, comment_id):
        comment = Comment.get_by_id(int(comment_id))
        if comment:
            comment.key.delete()
            return True
        else:
            return False
