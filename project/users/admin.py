from django import forms
from django.contrib import admin
from .models import User, EmailAddress, SocialAccount, SocialToken

class UserAdmin(admin.ModelAdmin):
    list_display = ('email', 'username', 'first_name', 'last_name', 'phone_number')
    list_editable = ('first_name', 'last_name', 'phone_number')
    list_filter = ('email', 'phone_number')

class EmailAddressAdmin(admin.ModelAdmin):
    list_display = ('email', 'user', 'primary', 'verified')
    list_filter = ('primary', 'verified')
    search_fields = []
    raw_id_fields = ('user',)

    def get_search_fields(self, request):
        base_fields = ['first_name', 'last_name', 'email']
        return ['email'] + list(map(lambda a: 'user__' + a, base_fields))

class SocialAccountAdmin(admin.ModelAdmin):
    search_fields = []
    raw_id_fields = ('user',)
    list_display = ('user', 'uid', 'provider')
    list_filter = ('provider',)

    def get_search_fields(self, request):
        base_fields = ['username', 'email', 'first_name', 'last_name']
        return list(map(lambda a: 'user__' + a, base_fields))


class SocialTokenAdmin(admin.ModelAdmin):
    raw_id_fields = ('account',)
    list_display = ('account', 'truncated_token', 'expires_at')
    list_filter = ('account__provider', 'expires_at')

    def truncated_token(self, token):
        max_chars = 40
        ret = token.token
        if len(ret) > max_chars:
            ret = ret[0:max_chars] + '...(truncated)'
        return ret


admin.site.register(User, UserAdmin)
admin.site.register(EmailAddress, EmailAddressAdmin)
admin.site.register(SocialToken, SocialTokenAdmin)
admin.site.register(SocialAccount, SocialAccountAdmin)
