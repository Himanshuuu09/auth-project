from django.shortcuts import render
import jwt
from datetime import datetime, timedelta
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from rest_framework import status
from .serializers import Notesserializers
from functools import wraps
from django.conf import settings
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
from .models import notes
from django.utils import timezone
import os


# Your JWT secret key
secret_key = os.getenv("SECRET_KEY")
# Create your views here.
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

@api_view(["POST"])
@token_required  # Applying the token_required decorator
def create_notes(request):
    try:
        token = request.COOKIES.get('jwt')
        payload = jwt.decode(token, secret_key, algorithms=["HS256"])
        email = payload.get('email')
        print(email)
        if not email:
            return Response({"message": "Login again."}, status=status.HTTP_401_UNAUTHORIZED)

        # Get and validate request data
        title = request.data.get('title')
        content = request.data.get('description')
        if not title or not content:
            return Response({"message": "Both title and description are required."}, status=status.HTTP_400_BAD_REQUEST)

        # Prepare data for serializer
        note_data = {
            "title": title,
            "content": content,
            "email": email  # If your `notes` model has an email field
        }

        serializer = Notesserializers(data=note_data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Note created successfully"}, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        # Log the exception details for debugging (optional, replace print with logging in production)
        print(f"Unexpected error: {str(e)}")  # Replace with logging if needed
        return Response({"message": "An internal server error occurred."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(["GET"])
@token_required  # Applying the token_required decorator
# @permission_classes([IsAuthenticated])
def get_notes(request):
    try:
        token = request.COOKIES.get('jwt')
        payload = jwt.decode(token, secret_key, algorithms=["HS256"])
        email = payload.get('email')
        if not email:
            return Response({"message": "Login again."}, status=status.HTTP_401_UNAUTHORIZED)
        # Get all notes for the authenticated user
        user_notes = notes.objects.filter(email=email)
        if not user_notes.exists():
            return Response({"message": "No notes found."}, status=status.HTTP_404_NOT_FOUND)
        serializer = Notesserializers(user_notes, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except Exception as e:
        # Log the exception details for debugging (optional)
        return Response({"message": "An internal server error occurred."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    



@api_view(["PUT"])
def update_notes(request):
    try:
        token = request.COOKIES.get('jwt')
        if not token:
            return Response({"message": "Authentication token is missing. Please log in."}, status=status.HTTP_401_UNAUTHORIZED)

        # Decode the token to get user's email
        try:
            payload = jwt.decode(token, secret_key, algorithms=["HS256"])
            email = payload.get('email')
            if not email:
                return Response({"message": "Invalid token payload."}, status=status.HTTP_401_UNAUTHORIZED)
        except ExpiredSignatureError:
            return Response({"message": "Token has expired. Please log in again."}, status=status.HTTP_401_UNAUTHORIZED)
        except InvalidTokenError:
            return Response({"message": "Invalid token. Please log in again."}, status=status.HTTP_401_UNAUTHORIZED)

        # Get note_id from query params and validate it
        note_id = request.query_params.get('id')
        if not note_id:
            return Response({"message": "Note ID is required."}, status=status.HTTP_400_BAD_REQUEST)

        # Fetch the note for the authenticated user
        try:
            note = notes.objects.get(id=note_id, email=email)
        except notes.DoesNotExist:
            return Response({"message": "Note not found."}, status=status.HTTP_404_NOT_FOUND)

        # Validate title and description fields
        title = request.data.get("title")
        description = request.data.get("description")
        if not title or not description:
            return Response({"message": "Both title and description are required."}, status=status.HTTP_400_BAD_REQUEST)

        # Update the note and save
        note.title = title
        note.description = description
        note.updated_at = timezone.now()
        note.save()

        # Serialize and return updated note data
        serializer = Notesserializers(note)
        return Response(serializer.data, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({"message": "An internal server error occurred."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(["DELETE"])
def delete_notes(request):
    try:
        token = request.COOKIES.get('jwt')
        if not token:
            return Response({"message": "Authentication token is missing. Please log in."}, status=status.HTTP_401_UNAUTHORIZED)

        # Decode the token to get user's email
        try:
            payload = jwt.decode(token, secret_key, algorithms=["HS256"])
            email = payload.get('email')
            if not email:
                return Response({"message": "Invalid token payload."}, status=status.HTTP_401_UNAUTHORIZED)
        except ExpiredSignatureError:
            return Response({"message": "Token has expired. Please log in again."}, status=status.HTTP_401_UNAUTHORIZED)
        except InvalidTokenError:
            return Response({"message": "Invalid token. Please log in again."}, status=status.HTTP_401_UNAUTHORIZED)

        # Get note_id from query params
        note_id = request.query_params.get('id')
        if not note_id:
            return Response({"message": "Note ID is required."}, status=status.HTTP_400_BAD_REQUEST)

        # Find the note for the authenticated user
        try:
            note = notes.objects.get(id=note_id, email=email)
        except notes.DoesNotExist:
            return Response({"message": "Note not found."}, status=status.HTTP_404_NOT_FOUND)

        # Delete the note
        note.delete()
        return Response({"message": "Note deleted successfully."}, status=status.HTTP_204_NO_CONTENT)

    except Exception as e:
        return Response({"message": "An internal server error occurred."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                            
