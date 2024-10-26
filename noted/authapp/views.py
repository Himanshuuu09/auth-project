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
import jwt
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated,AllowAny
from django.core.mail import send_mail
from django.conf import settings
import random
import asyncio
from functools import wraps


# Load environment variables from .env file
load_dotenv()

secret_key = os.getenv("SECRET_KEY")

def token_required(view_func):
    @wraps(view_func)
    def wrapped_view(request, *args, **kwargs):
        token = request.COOKIES.get('jwt')
        if not token:
            return Response({"message": "Authentication token is missing. Please log in."}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            # Decode the token
            payload = jwt.decode(token, secret_key, algorithms=["HS256"])
            # Check token expiration
            if datetime.fromtimestamp(payload['exp']) < datetime.utcnow():
                return Response({"message": "Token has expired. Please log in again."}, status=status.HTTP_401_UNAUTHORIZED)

        except jwt.ExpiredSignatureError:
            return Response({"message": "Token has expired. Please log in again."}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({"message": "Invalid token. Please log in again."}, status=status.HTTP_401_UNAUTHORIZED)

        return view_func(request, *args, **kwargs)

    return wrapped_view


@api_view(['POST'])
@permission_classes([AllowAny])  # Allow anyone to sign in
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

        
        serializer = UserSerializer(user)
        payload={
            "email":serializer.data["email"],
            "exp": datetime.utcnow() + timedelta(minutes=60),
            "iat": datetime.utcnow()
        }
        token=jwt.encode(payload,secret_key,algorithm="HS256")
        response = Response(status=status.HTTP_200_OK)
        response.set_cookie(key='jwt', value=token, httponly=True)
        response.data = {"jwt": token}
        return response
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
        subject="Welcome to Noteit"
        message="Your account has been created successfully"
        send_welcome_email(email_address=user.email,subject=subject,message=message)
        return Response({"token":token.key,"user":serializer.data})
    return Response(serializer.errors,status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
def create_user(request):
    token_key = request.query_params.get('token')
    
@api_view(['GET'])
@token_required
def logout_view(request):
    response = Response({"message": "Logged out successfully"}, status=status.HTTP_200_OK)
    try:
        # Attempt to delete the JWT cookie
        response.delete_cookie("jwt")
    except Exception as e:
        # Log or handle any exceptions that may occur while deleting the cookie
        return Response({"error": "Failed to log out"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    return response


def send_welcome_email(email_address,subject,message):
    subject = subject
    message = message
    from_email = settings.EMAIL_HOST_USER  # The email address from which the email will be sent

    try:
        send_mail(subject, message, from_email, [email_address])
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

def otp_generate():
    return str(random.randint(100000, 999999))

@api_view(['POST'])
def send_otp(request):
    try:
        email=request.data["email"]
        users=User.objects.filter(email=email).exists()
        if users:
            otps=otp_generate()
            payload={
            "otp":otps,
            "email":email,
            "exp": datetime.utcnow() + timedelta(minutes=60),
            "iat": datetime.utcnow(),
        }
            token=jwt.encode(payload,secret_key,algorithm="HS256")
            response = Response(status=status.HTTP_200_OK)
            response.set_cookie(key='jwt', value=token, httponly=True)
            response.data = {"jwt": token}
            print(response.data)
            return Response({"message": "otp send successfully"}, status=status.HTTP_200_OK)
        else:
            return Response({"message": "user not found"}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({"message": "error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
@api_view(['POST'])
def forget_pwd(request):
    token_key = request.query_params.get('token')
    
    # Check if the token is provided
    if not token_key:
        return Response({"detail": "Token is required"}, status=status.HTTP_400_BAD_REQUEST)
    try:
        payload = jwt.decode(token_key, secret_key, algorithms=["HS256"])
        email = payload.get("email")
        otp=payload.get("otp")
        if otp:
            new_password=request.data.get("password")
            user = User.objects.get(email=email)
            user.set_password(new_password)  # Update the password
            user.save()
            return Response({"message": "Password updated successfully"}, status=status.HTTP_200_OK)
        else:
            return Response({"message": "invalid otp"}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response({"message": "error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            

            




