from django.contrib.auth import get_user_model
User = get_user_model()
print("-" * 30)
for u in User.objects.all():
    print(f"ID: {u.id} | Username: {u.username} | Email: {u.email}")
print("-" * 30)
