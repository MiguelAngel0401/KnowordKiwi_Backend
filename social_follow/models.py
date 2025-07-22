import uuid
from django.db import models
from django.core.exceptions import ValidationError
from users.models import User

class UserRelationship(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    follower = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='following'
    )
    # Usuario que sigue a otro

    following = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='followers'
    )
    # Usuario que está siendo seguido

    created_at = models.DateTimeField(auto_now_add=True)
    

    class Meta:
        db_table = 'user_follows'
        unique_together = ('follower', 'following')
        indexes = [
            models.Index(fields=['follower']),
            models.Index(fields=['following']),
            
        ]
        constraints = [
            models.CheckConstraint(
                check=~models.Q(follower=models.F('following')),
                name='prevent_self_follow'
                
            )
        ]
        verbose_name = 'Seguimiento de Usuario'
        verbose_name_plural = 'Seguimientos de Usuarios'
        

    def clean(self):
        if self.follower == self.following:
            raise ValidationError("Un usuario no puede seguirse a sí mismo.")
        

    def save(self, *args, **kwargs):
        self.clean()
        super().save(*args, **kwargs)
        

    def __str__(self):
        return f"{self.follower.username} sigue a {self.following.username}"
    
    
class UserFollow(UserRelationship):
    class Meta:
        proxy = True
        verbose_name = 'Alias de Seguimiento'
        verbose_name_plural = 'Alias de Seguimientos'
