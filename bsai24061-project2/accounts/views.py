from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import get_user_model, authenticate, login as auth_login, logout as auth_logout
from django.contrib.auth.hashers import make_password
from django.contrib.auth.decorators import login_required

User = get_user_model()  # This will use your custom Users model


def login(request):
    """Handle user login"""
    if request.method == "POST":
        email = request.POST.get("email") or request.POST.get("username")
        password = request.POST.get("password")

        # Validation
        if not email or not password:
            messages.error(request, "Email and password are required.")
            return redirect('login')

        # Authenticate the user
        user = authenticate(request, username=email, password=password)

        if user is not None:
            # Login successful
            auth_login(request, user)
            messages.success(request, f"Welcome back, {user.name}!")
            return redirect('home')  # Redirect to home page
        else:
            # Login failed
            messages.error(request, "Invalid email or password.")
            return redirect('login')

    return render(request, "login.html")


def register(request):
    """Handle user registration"""
    if request.method == "POST":
        email = request.POST.get("email")
        name = request.POST.get("name")
        password = request.POST.get("password")
        confirm_password = request.POST.get("confirm_password")

        # Validation
        if not email or not name or not password:
            messages.error(request, "All fields are required.")
            return redirect('register')

        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return redirect('register')

        if User.objects.filter(email=email).exists():
            messages.error(request, "Email is already registered.")
            return redirect('register')

        # Create the user
        user = User.objects.create(
            email=email,
            name=name,
            password=make_password(password)  # Hash the password
        )

        messages.success(request, "Account created successfully! You can now log in.")
        return redirect('login')

    return render(request, "register.html")


@login_required(login_url='login')
def home(request):
    """Home page - shows logged in user info"""
    return render(request, "home.html")


def logout(request):
    """Handle user logout"""
    auth_logout(request)
    messages.success(request, "You have been logged out successfully.")
    return redirect('login')