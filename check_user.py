from django.contrib.auth import get_user_model
try:
    User = get_user_model()
    username = 'kirimievansgitonga'
    with open('found_user.txt', 'w') as f:
        try:
            users = User.objects.filter(email__icontains=username)
            if users.exists():
                for user in users:
                    f.write(f"FOUND|{user.email}|{user.role}\n")
            else:
                f.write(f"NOT_FOUND|{username}")
        except Exception as e:
            f.write(f"ERROR|{str(e)}")
except Exception as e:
    with open('found_user.txt', 'w') as f:
        f.write(f"OUTER_ERROR|{str(e)}")
