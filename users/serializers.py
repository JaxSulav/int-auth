from django.contrib.auth import get_user_model
from rest_framework import serializers

User = get_user_model()


class UserCreationSerializer(serializers.Serializer):
    password = serializers.CharField(required=True)
    password1 = serializers.CharField(required=True)
    username = serializers.CharField(required=True)
    email = serializers.CharField(required=True)

    class Meta:
        fields = ("username", "email", "password", "password1")

    def validate(self, attrs):
        if User.objects.filter(username=attrs.get("username")).exists():
            raise serializers.ValidationError({"username": "User with this username already exists."})
        if User.objects.filter(email=attrs.get("email")).exists():
            raise serializers.ValidationError({"email": "User with this email already exists."})
        if not attrs.get("password") == attrs.get("password1"):
            raise serializers.ValidationError({"password": "Passwords do not match."})
        return attrs
