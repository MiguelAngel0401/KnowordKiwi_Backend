import uuid
from django.db import models
from users.models import User
from publications.models import Post  # Asumiendo que Post está en publications

class PostReaction(models.Model):
    class ReactionType(models.TextChoices):
        LIKE = 'like', 'Me gusta'
        LOVE = 'love', 'Me encanta'
        LAUGH = 'laugh', 'Me da risa'
        WOW = 'wow', 'Me sorprende'
        SAD = 'sad', 'Me entristece'
        ANGRY = 'angry', 'Me enoja'
        HELPFUL = 'helpful', 'Me ayuda'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name='reactions')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='post_reactions')
    reaction_type = models.CharField(max_length=20, choices=ReactionType.choices)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('post', 'user')
        verbose_name = 'Reacción'
        verbose_name_plural = 'Reacciones'

    def __str__(self):
        return f"{self.user} reaccionó con {self.reaction_type} al post {self.post.id}"


class PostComment(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name='comments')
    author = models.ForeignKey(User, on_delete=models.CASCADE, related_name='post_comments')
    parent_comment = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True, related_name='replies')
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=['post']),
            models.Index(fields=['parent_comment']),
        ]
        verbose_name = 'Comentario'
        verbose_name_plural = 'Comentarios'

    def __str__(self):
        return f"Comentario de {self.author} en {self.post.id}"


class PostShare(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    original_post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name='shares')
    shared_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='shared_posts')
    caption = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('original_post', 'shared_by')
        verbose_name = 'Compartir'
        verbose_name_plural = 'Compartidos'

    def __str__(self):
        return f"{self.shared_by} compartió el post {self.original_post.id}"


