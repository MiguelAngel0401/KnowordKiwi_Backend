import uuid
from django.db import models
from users.models import User


class Post(models.Model):
    class PostType(models.TextChoices):
        IMAGE = 'image', 'Imagen'
        VIDEO = 'video', 'Video'
        BLOG = 'blog', 'Blog'
        QUESTION = 'question', 'Pregunta'
        LINK = 'link', 'Enlace'
        QUIZ = 'quiz', 'Quiz'
        POLL = 'poll', 'Encuesta'
        

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    

    author = models.ForeignKey(User, on_delete=models.CASCADE, related_name='posts')


    #Aqui use esta forma de las community para manadra a traerla aunque la app no este en esta rama cuando se haga el merge
    #en teoria deberia de fucnionar si no importamos directamente el modelo
    
    
    community = models.ForeignKey(
        'communities.Community',
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name='posts'
    )

    post_type = models.CharField(max_length=20, choices=PostType.choices)
    

    title = models.CharField(max_length=200, blank=True, null=True)
    content = models.TextField(blank=True, null=True)
    

    media_urls = models.JSONField(blank=True, null=True)
    link_url = models.URLField(max_length=500, blank=True, null=True)
    

    is_community_only = models.BooleanField(default=False)
    

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(blank=True, null=True)
    

    class Meta:
        db_table = 'posts'
        indexes = [
            models.Index(fields=['author']),
            models.Index(fields=['community']),
            models.Index(fields=['-created_at']),
            models.Index(fields=['post_type']),
        ]
        verbose_name = 'Publicación'
        verbose_name_plural = 'Publicaciones'
        

    def __str__(self):
        return f"{self.post_type.upper()} - {self.title or '[Sin título]'} por {self.author.username}"
