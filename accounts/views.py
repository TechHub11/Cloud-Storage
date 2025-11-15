from django.shortcuts import render, redirect
from django.contrib.auth import login
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import Profile
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login as auth_login


def register(request):
    if request.user.is_authenticated:
        return redirect('index')
    else:
        if request.method == 'POST':
            username = request.POST['username']
            email = request.POST['email']
            password = request.POST['password']
            cpassword = request.POST['cpassword']
            firstname = request.POST['fname']
            lname = request.POST['lname']
            if username and password and email and cpassword and firstname and lname:
                if password == cpassword:
                    user = User.objects.create_user(username,email,password)
                    user.first_name = firstname
                    user.last_name = lname
                    user.save()
                    if user:
                        messages.success(request,"User Account Created")
                        return redirect("login")
                    else:
                        messages.error(request,"User Account Not Created")
                else:
                    messages.error(request,"Password Not Matched")
                    redirect("register")
        return render(request,'registration/register.html')
        

def login(request):
    if request.method == "POST":
        username = request.POST["username"]
        password = request.POST["password"]
        user = authenticate(request, username=username, password=password)
        if user is not None:
            auth_login(request, user)  # ✅ call Django’s login
            return redirect("index")    # change to your success page
        else:
            return render(request, "login.html", {"error": "Invalid username or password"})
    return render(request, "login.html")
        #return render(request, "home/login.html",)

from .models import Profile


from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.core.mail import send_mail
from django.shortcuts import render, redirect
from django.contrib import messages
from django.conf import settings
from django.urls import reverse


def forgot_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            user = User.objects.get(email=email)
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))

            # ✅ Use reverse() to generate the correct URL dynamically
            reset_link = request.build_absolute_uri(
                reverse('reset_password', kwargs={'uidb64': uid, 'token': token})
            )

            # ✅ Send email
            send_mail(
                'Password Reset - PiCloud',
                f'Hello {user.username},\n\nClick below to reset your password:\n{reset_link}\n\nIf you did not request this, ignore this email.',
                settings.DEFAULT_FROM_EMAIL,
                [email],
                fail_silently=False,
            )
            messages.success(request, "Password reset link sent to your email.")
        except User.DoesNotExist:
            messages.error(request, "No account found with this email.")
    return render(request, 'registration/forgot_password.html')


def reset_password(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except (User.DoesNotExist, ValueError, TypeError, OverflowError):
        user = None

    if user and default_token_generator.check_token(user, token):
        if request.method == 'POST':
            password = request.POST.get('password')
            confirm = request.POST.get('confirm')
            if password == confirm:
                user.set_password(password)
                user.save()
                messages.success(request, "Password reset successfully.")
                return redirect('login')  # ✅ Redirect to login after reset
            else:
                messages.error(request, "Passwords do not match.")
        return render(request, 'registration/reset_password.html')
    else:
        messages.error(request, "Invalid or expired link.")
        return redirect('registration/forgot_password')  # ✅ Use name, not template path


@login_required
def profile(request):
    return render(request, "accounts/profile.html") 


