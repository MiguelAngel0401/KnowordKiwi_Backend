from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User

class UserAdmin(BaseUserAdmin):
    model = User
    list_display = ('email', 'username', 'real_name', 'is_staff', 'is_active')
    list_filter = ('is_staff', 'is_active')
    ordering = ('email',)
    search_fields = ('email', 'username', 'real_name')
    
    readonly_fields = ('created_at', 'updated_at')  # mostrar pero no editar
    
    fieldsets = (
        (None, {'fields': ('email', 'username', 'real_name', 'password')}),
        ('Permisos', {'fields': ('is_staff', 'is_active', 'is_superuser', 'groups', 'user_permissions')}),
        ('Fechas', {'fields': ('last_login', 'created_at', 'updated_at')}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'username', 'real_name', 'password1', 'password2', 'is_staff', 'is_active'),
        }),
    )

admin.site.register(User, UserAdmin)
