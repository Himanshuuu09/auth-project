from django.shortcuts import render
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from .serializers import UserSerializer
from rest_framework.authtoken.models import Token
from django.contrib.auth.models import User
# Create your views here.
from django.shortcuts import get_object_or_404
from django.contrib.auth import authenticate


@api_view(['POST'])
def login(request):
    username = request.data.get("username")
    password = request.data.get("password")

    if not username or not password:
        return Response({"details": "Username and password are required."}, status=status.HTTP_400_BAD_REQUEST)
    try:
        if "@" in username:
            user = User.objects.get(email=username)
            username = user.username
        user = authenticate(username=username, password=password)

        if user is None:
            return Response({"details": "Invalid username or password"}, status=status.HTTP_401_UNAUTHORIZED)

        token, created = Token.objects.get_or_create(user=user)
        serializer = UserSerializer(user)
        
        return Response({"token": token.key, "user": serializer.data}, status=status.HTTP_200_OK)
    except Exception as e:
        # Log the exception (optional)
        print(f"Error during login: {str(e)}")  # Replace with a proper logging mechanism

        return Response({"details": "An error occurred during login. Please try again."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
@api_view(['POST'])
def signup(request):
    serializer = UserSerializer(data=request.data)
    users=User.objects.filter(email=request.data["email"]).exists()
    print("yes")
    if users:
        exist=True
    else:
        exist=False
    if serializer.is_valid() and exist==False:
        serializer.save()
        user=User.objects.get(username=request.data['username'])
        user.set_password(request.data['password'])
        user.save()
        token=Token.objects.create(user=user)
        return Response({"token":token.key,"user":serializer.data})
    return Response(serializer.errors,status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
def test_token(request):
    return Response({})