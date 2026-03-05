
def check_admin(user):
    if not user.is_admin:
        raise PermissionError('User must be admin')
    return 'Secret Data'