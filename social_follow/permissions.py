from rest_framework import permissions

class Seguir(permissions.BasePermission): 

    def has_object_permission(self, request, view, obj):
     
        if request.method in permissions.SAFE_METHODS:
            return True

        # Aquí específicamente pide que el usuario esté registrado para poder seguirlo (solo el follower puede modificar/eliminar)
        return obj.follower == request.user 


class Siguiendo(permissions.BasePermission):

    def has_permission(self, request, view):

        if request.method != 'POST':
            return True

        # Aquí pide que el usuario que mande la solicitud sea el que aparezca en la solicitud (solo puedes crear si tú eres el follower)
        follower_id = request.data.get('follower')
        return str(request.user.id) == follower_id
