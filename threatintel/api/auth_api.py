
from django.contrib.auth.models import User
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError


@api_view(["POST"])
@permission_classes([AllowAny])
@throttle_classes([AnonRateThrottle, UserRateThrottle])
def register(request):
    username = request.data.get("username", "").strip()
    password = request.data.get("password", "").strip()
    email    = request.data.get("email", "").strip()

    if not username or not password:
        return Response(
            {"error": "Username and password are required."},
            status=status.HTTP_400_BAD_REQUEST
        )

    if User.objects.filter(username=username).exists():
        return Response(
            {"error": "Username already exists."},
            status=status.HTTP_400_BAD_REQUEST
        )

    user = User.objects.create_user(username=username, password=password, email=email)
    refresh = RefreshToken.for_user(user)

    return Response({
        "message": "User created successfully.",
        "username": user.username,
        "access":  str(refresh.access_token),
        "refresh": str(refresh),
    }, status=status.HTTP_201_CREATED)


@api_view(["POST"])
@permission_classes([AllowAny])
@throttle_classes([AnonRateThrottle, UserRateThrottle])
def login(request):
    username = request.data.get("username", "").strip()
    password = request.data.get("password", "").strip()

    if not username or not password:
        return Response(
            {"error": "Username and password are required."},
            status=status.HTTP_400_BAD_REQUEST
        )

    from django.contrib.auth import authenticate
    user = authenticate(username=username, password=password)

    if not user:
        return Response(
            {"error": "Invalid credentials."},
            status=status.HTTP_401_UNAUTHORIZED
        )

    refresh = RefreshToken.for_user(user)
    return Response({
        "username": user.username,
        "access":   str(refresh.access_token),
        "refresh":  str(refresh),
    })


@api_view(["POST"])
@permission_classes([AllowAny])
@throttle_classes([AnonRateThrottle, UserRateThrottle])
def refresh_token(request):
    token = request.data.get("refresh")
    if not token:
        return Response({"error": "Refresh token required."}, status=status.HTTP_400_BAD_REQUEST)
    try:
        refresh = RefreshToken(token)
        return Response({"access": str(refresh.access_token)})
    except TokenError as e:
        return Response({"error": str(e)}, status=status.HTTP_401_UNAUTHORIZED)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
@throttle_classes([UserRateThrottle])
def logout(request):
    token = request.data.get("refresh")
    if not token:
        return Response({"error": "Refresh token required."}, status=status.HTTP_400_BAD_REQUEST)
    try:
        RefreshToken(token).blacklist()
    except Exception:
        pass
    return Response({"message": "Logged out successfully."})


@api_view(["GET"])
@permission_classes([IsAuthenticated])
@throttle_classes([UserRateThrottle])
def me(request):
    return Response({
        "id":       request.user.id,
        "username": request.user.username,
        "email":    request.user.email,
        "is_staff": request.user.is_staff,
    })


from django.contrib.auth.models import User
from rest_framework.permissions import IsAdminUser

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def list_users(request):
    """GET /api/auth/users/"""
    if not request.user.is_staff:
        return Response({"error": "Admin access required."}, status=status.HTTP_403_FORBIDDEN)
    users = User.objects.all().order_by('-date_joined')
    data = [{
        "id":           u.id,
        "username":     u.username,
        "email":        u.email,
        "is_staff":     u.is_staff,
        "is_active":    u.is_active,
        "date_joined":  u.date_joined,
        "last_login":   u.last_login,
    } for u in users]
    return Response({"count": len(data), "results": data})


@api_view(["DELETE"])
@permission_classes([IsAuthenticated])
def delete_user(request, user_id):
    """DELETE /api/auth/users/<id>/"""
    if not request.user.is_staff:
        return Response({"error": "Admin access required."}, status=status.HTTP_403_FORBIDDEN)
    try:
        user = User.objects.get(id=user_id)
        if user == request.user:
            return Response({"error": "Cannot delete yourself."}, status=status.HTTP_400_BAD_REQUEST)
        user.delete()
        return Response({"message": "User deleted."})
    except User.DoesNotExist:
        return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)
